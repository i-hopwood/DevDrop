using Avalonia.Controls;
using System;

namespace DevDrop_UI.Views
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);

            // Cleanup ViewModel when window closes
            if (DataContext is IDisposable disposable)
            {
                disposable.Dispose();
            }
        }
    }
}   