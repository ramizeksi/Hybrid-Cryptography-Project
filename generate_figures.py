"""
generate_figures.py - Generates Figure 9 and Figure 10 for the report.

Figure 9: Box-and-whisker plot of latency distributions for X25519, ML-KEM-768, Hybrid
Figure 10: Hybrid overhead percentage vs file size (log scale)

Usage:
    python generate_figures.py

Requires:
    pip install matplotlib

Output files (saved in current directory):
    - figure9_latency_boxplot.png
    - figure10_overhead_vs_filesize.png
"""

import sys
import os

try:
    import matplotlib.pyplot as plt
    import matplotlib
except ImportError:
    print("ERROR: matplotlib is required. Install with: pip install matplotlib")
    sys.exit(1)

import crypto_engine as ce


# Style settings for IEEE-quality figures
matplotlib.rcParams['font.family'] = 'serif'
matplotlib.rcParams['font.size'] = 11
matplotlib.rcParams['axes.labelsize'] = 12
matplotlib.rcParams['axes.titlesize'] = 13
matplotlib.rcParams['xtick.labelsize'] = 10
matplotlib.rcParams['ytick.labelsize'] = 10
matplotlib.rcParams['legend.fontsize'] = 10
matplotlib.rcParams['figure.dpi'] = 150


def generate_figure_9(iterations: int = 10000):
    """
    Figure 9: Box-and-whisker plot showing latency distribution
    for X25519, ML-KEM-768, and Hybrid (sum) configurations.
    """
    print(f"[FIG 9] Running benchmark with {iterations} iterations...")
    print("[FIG 9] This will take a few seconds...")
    
    results = ce.run_benchmark(iterations=iterations)
    
    # Convert seconds to milliseconds
    x25519_ms = [t * 1000 for t in results['x25519_times']]
    mlkem_ms = [t * 1000 for t in results['mlkem_times']]
    # Pair-wise sum for hybrid
    hybrid_ms = [a + b for a, b in zip(x25519_ms, mlkem_ms)]
    
    fig, ax = plt.subplots(figsize=(7, 5))
    
    bp = ax.boxplot(
        [x25519_ms, mlkem_ms, hybrid_ms],
        labels=['X25519\n(Classical)', 'ML-KEM-768\n(Post-Quantum)', 'Hybrid\n(X25519 + ML-KEM)'],
        patch_artist=True,
        showmeans=True,
        meanprops={'marker': 'D', 'markerfacecolor': 'red', 'markeredgecolor': 'red', 'markersize': 6},
        medianprops={'color': 'black', 'linewidth': 2},
        boxprops={'linewidth': 1.2},
        whiskerprops={'linewidth': 1.2},
        capprops={'linewidth': 1.2},
        flierprops={'marker': 'o', 'markersize': 3, 'alpha': 0.3},
    )
    
    # Color each box
    colors = ['#3498db', '#9b59b6', '#2ecc71']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
    
    ax.set_ylabel('Latency per Session (ms)')
    ax.set_title(f'Latency Distribution Across {iterations:,} Iterations')
    ax.grid(True, axis='y', linestyle='--', alpha=0.5)
    ax.set_axisbelow(True)
    
    # Annotate means
    means = [
        sum(x25519_ms) / len(x25519_ms),
        sum(mlkem_ms) / len(mlkem_ms),
        sum(hybrid_ms) / len(hybrid_ms),
    ]
    for i, m in enumerate(means, start=1):
        ax.annotate(
            f'μ = {m:.4f} ms',
            xy=(i, m),
            xytext=(i + 0.15, m),
            fontsize=9,
            color='darkred',
            va='center',
        )
    
    # Legend for the red diamond marker
    from matplotlib.lines import Line2D
    legend_elem = [
        Line2D([0], [0], marker='D', color='w', markerfacecolor='red',
               markersize=8, label='Mean'),
        Line2D([0], [0], color='black', linewidth=2, label='Median'),
    ]
    ax.legend(handles=legend_elem, loc='upper left')
    
    plt.tight_layout()
    out_path = 'figure9_latency_boxplot.png'
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[FIG 9] Saved: {out_path}")
    
    # Also save a PDF version for LaTeX
    pdf_path = 'figure9_latency_boxplot.pdf'
    fig2, ax2 = plt.subplots(figsize=(7, 5))
    bp2 = ax2.boxplot(
        [x25519_ms, mlkem_ms, hybrid_ms],
        labels=['X25519\n(Classical)', 'ML-KEM-768\n(Post-Quantum)', 'Hybrid'],
        patch_artist=True, showmeans=True,
        meanprops={'marker': 'D', 'markerfacecolor': 'red', 'markeredgecolor': 'red'},
    )
    for patch, color in zip(bp2['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
    ax2.set_ylabel('Latency per Session (ms)')
    ax2.set_title(f'Latency Distribution ({iterations:,} iterations)')
    ax2.grid(True, axis='y', linestyle='--', alpha=0.5)
    plt.tight_layout()
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.close()
    print(f"[FIG 9] Saved: {pdf_path}")
    
    return results


def generate_figure_10(benchmark_results: dict = None):
    """
    Figure 10: Hybrid overhead percentage vs file size (log scale on X axis).
    
    Mathematical model:
      total_time(file_size) = asymmetric_time + (file_size / aes_throughput)
      hybrid_overhead_pct = (mlkem_time / total_time) * 100
    
    The asymmetric phase cost (mlkem_time) is fixed. As the file grows,
    AES-GCM time dominates, so the hybrid overhead percentage approaches 0.
    """
    print("[FIG 10] Generating overhead vs file size figure...")
    
    if benchmark_results is None:
        print("[FIG 10] No benchmark data provided, running quick benchmark...")
        benchmark_results = ce.run_benchmark(iterations=5000)
    
    # Asymmetric costs (in seconds)
    x25519_only_sec = benchmark_results['x25519_avg_ms'] / 1000
    mlkem_only_sec = benchmark_results['mlkem_avg_ms'] / 1000
    hybrid_sec = x25519_only_sec + mlkem_only_sec
    
    # Assumed AES-GCM throughput (MB/s) — modern CPU with AES-NI
    # You can adjust this based on actual measurement on your hardware
    AES_THROUGHPUT_MBPS = 1000.0
    
    # File sizes from 1 MB to 10 GB (log scale)
    file_sizes_mb = [1, 5, 10, 50, 100, 500, 1000, 5000, 10000]
    
    overhead_pct_list = []
    overhead_abs_list = []
    
    for size_mb in file_sizes_mb:
        aes_time_sec = size_mb / AES_THROUGHPUT_MBPS
        total_classical_sec = x25519_only_sec + aes_time_sec
        total_hybrid_sec = hybrid_sec + aes_time_sec
        
        # Overhead = extra cost from adding ML-KEM relative to classical-only
        overhead_abs = (total_hybrid_sec - total_classical_sec) * 1000  # ms
        overhead_pct = (overhead_abs / 1000) / total_classical_sec * 100
        
        overhead_pct_list.append(overhead_pct)
        overhead_abs_list.append(overhead_abs)
    
    fig, ax1 = plt.subplots(figsize=(8, 5))
    
    color1 = '#e74c3c'
    ax1.set_xlabel('File Size (MB, log scale)')
    ax1.set_ylabel('Hybrid Overhead (%)', color=color1)
    line1 = ax1.semilogx(file_sizes_mb, overhead_pct_list,
                          'o-', color=color1, linewidth=2, markersize=8,
                          label='Relative overhead (%)')
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.grid(True, which='both', linestyle='--', alpha=0.4)
    ax1.set_axisbelow(True)
    
    # Secondary Y axis: absolute overhead in ms (constant line)
    ax2 = ax1.twinx()
    color2 = '#2980b9'
    ax2.set_ylabel('Absolute Overhead (ms)', color=color2)
    line2 = ax2.semilogx(file_sizes_mb, overhead_abs_list,
                          's--', color=color2, linewidth=1.5, markersize=6, alpha=0.7,
                          label='Absolute overhead (ms)')
    ax2.tick_params(axis='y', labelcolor=color2)
    ax2.set_ylim(0, max(overhead_abs_list) * 2)
    
    plt.title(f'Hybrid KEM Overhead vs File Size\n'
              f'(AES-GCM throughput assumed: {AES_THROUGHPUT_MBPS:.0f} MB/s)')
    
    # Combined legend
    lines = line1 + line2
    labels = [l.get_label() for l in lines]
    ax1.legend(lines, labels, loc='upper right')
    
    # Annotate key points
    ax1.annotate(
        f'{overhead_pct_list[0]:.1f}%',
        xy=(file_sizes_mb[0], overhead_pct_list[0]),
        xytext=(file_sizes_mb[0] * 1.5, overhead_pct_list[0] + 1),
        fontsize=9, color=color1,
    )
    ax1.annotate(
        f'{overhead_pct_list[-1]:.4f}%',
        xy=(file_sizes_mb[-1], overhead_pct_list[-1]),
        xytext=(file_sizes_mb[-1] * 0.3, overhead_pct_list[-1] + 0.5),
        fontsize=9, color=color1,
    )
    
    plt.tight_layout()
    out_path = 'figure10_overhead_vs_filesize.png'
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"[FIG 10] Saved: {out_path}")
    
    pdf_path = 'figure10_overhead_vs_filesize.pdf'
    # Re-save as PDF (matplotlib needs a fresh figure)
    fig, ax1 = plt.subplots(figsize=(8, 5))
    ax1.set_xlabel('File Size (MB, log scale)')
    ax1.set_ylabel('Hybrid Overhead (%)', color=color1)
    ax1.semilogx(file_sizes_mb, overhead_pct_list, 'o-', color=color1, linewidth=2, markersize=8)
    ax1.tick_params(axis='y', labelcolor=color1)
    ax1.grid(True, which='both', linestyle='--', alpha=0.4)
    ax2 = ax1.twinx()
    ax2.set_ylabel('Absolute Overhead (ms)', color=color2)
    ax2.semilogx(file_sizes_mb, overhead_abs_list, 's--', color=color2, linewidth=1.5, markersize=6, alpha=0.7)
    ax2.tick_params(axis='y', labelcolor=color2)
    ax2.set_ylim(0, max(overhead_abs_list) * 2)
    plt.title(f'Hybrid KEM Overhead vs File Size')
    plt.tight_layout()
    plt.savefig(pdf_path, bbox_inches='tight')
    plt.close()
    print(f"[FIG 10] Saved: {pdf_path}")
    
    # Print table for the report
    print("\n[FIG 10] Data for the report:")
    print(f"{'File Size':>12} {'Overhead %':>15} {'Overhead (ms)':>18}")
    print("-" * 50)
    for sz, pct, abs_ms in zip(file_sizes_mb, overhead_pct_list, overhead_abs_list):
        if sz < 1000:
            sz_str = f"{sz} MB"
        else:
            sz_str = f"{sz/1000:.0f} GB"
        print(f"{sz_str:>12} {pct:>14.4f}% {abs_ms:>17.4f}")


if __name__ == "__main__":
    print("=" * 60)
    print("  IEEE Report Figure Generator")
    print("  Hybrid KEM Cryptographic Benchmark")
    print("=" * 60)
    print()
    
    # Allow custom iteration count via CLI argument
    iterations = 10000
    if len(sys.argv) > 1:
        try:
            iterations = int(sys.argv[1])
        except ValueError:
            print(f"Invalid iteration count, using default {iterations}")
    
    print(f"Iterations: {iterations}")
    print()
    
    # Generate Figure 9 (and reuse benchmark data for Figure 10)
    benchmark_data = generate_figure_9(iterations)
    print()
    generate_figure_10(benchmark_data)
    
    print()
    print("=" * 60)
    print("  Done. Figures generated in current directory.")
    print("  PNG files: high resolution for review")
    print("  PDF files: vector format for LaTeX inclusion")
    print("=" * 60)
