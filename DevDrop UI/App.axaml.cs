using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using DevDrop_UI.ViewModels;
using DevDrop_UI.Views;

namespace DevDrop_UI
{
    public partial class App : Application
    {
        public override void Initialize()
        {
            AvaloniaXamlLoader.Load(this);
        }

        public override void OnFrameworkInitializationCompleted()
        {
            if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
            {
                // Avalonia 12 no longer registers the DataAnnotations validation plugin by default
                // (it is opt-in via AppBuilder.WithDataAnnotationsValidation), so there is nothing to
                // disable to avoid duplicate validation with CommunityToolkit.Mvvm.
                desktop.MainWindow = new MainWindow
                {
                    DataContext = new MainWindowViewModel(),
                };
            }

            base.OnFrameworkInitializationCompleted();
        }
    }
}