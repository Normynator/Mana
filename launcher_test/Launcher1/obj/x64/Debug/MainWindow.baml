   M S B A M L   `   `   `  ����D  @Launcher1, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null%clr-namespace:Launcher1	Launcher1  5   	       Launcher1.MainWindow   5   	   \ XPresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35R NWindowsBase, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35W SPresentationCore, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35D 9http://schemas.microsoft.com/winfx/2006/xaml/presentation    5   	   R NSystem.Xaml, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089:x,http://schemas.microsoft.com/winfx/2006/xaml     5   	   @d2http://schemas.microsoft.com/expression/blend/2008     5   	   Jmc;http://schemas.openxmlformats.org/markup-compatibility/2006     5   	   J FXamlAnimatedGif, Version=1.2.0.0, Culture=neutral, PublicKeyToken=null<gif2https://github.com/XamlAnimatedGif/XamlAnimatedGif  5      #localclr-namespace:Launcher1  5   	     � Title$  
MainWindow��5	   	   $	��700��6   $
��1200��6)    � WindowStyle$
 None=�5
       � AllowsTransparency . ��5      �� 5       �� ImageSource$B <C:\Users\norm\source\repos\Launcher1\Launcher1\Data\bg2.jpeg��6   .��5      � .+�5      �� $	��Top=�6   $��Center=�6&   �� 5      -   5         �� TextDecorations$
 None{�5   ,   .�6C   .�5      �� $	��240��5      $��0,10,0,0q�5      $	��666��5      $M��GC:\Users\norm\source\repos\Launcher1\Launcher1\Data\Einherjar_Logo2.png��5      6Z   5      5      �� 5      $��850,280,0,0q�6   �� 5      -   5        $
 None{�5   '   .�6>   .�5      �� $	��100��5      $J��DC:\Users\norm\source\repos\Launcher1\Launcher1\Data\discord_logo.png��5      6W   5      5      �� 5!      -   5        $
��btn1��5!      $��X��6   
�������$��50��6:   $��30��6E   $��1150,0,0,670q�6l   ���#2e3130 J� Opacity$	 0.5Q�6�   �� 5"      -   5        $
��btn2��5"      $��--��6   
�������$��50��6;   $��30��6F   $��1050,0,0,670q�6l   ���#2e3130$	 0.5Q�6�   �� 5#      
�������$��2q�6   ���#2e3137$��	0,210,0,0q�6H   $	��425��6[   $	��400��6h   $	 0.9Q�6t   ._�5$      �� .+�5%      �� $��Login��6   
�������$��Calibri)�6/   $	��Top=�6D   $��Center=�6\   $��30(�6y   $��48,20,160,0q�6�   $	��188��6�   $��48��6�   �� 5&      -   5        $��tbLogin��5&      $	��300��6   $��40��6)   $	 0.3Q�65   $��30(�6C   $��0,0,0,5q�6Q   G� 5'      -   5        $��
tbPassword��5'      $	��300��6$   $��40��60   $	 0.3Q�6<   $��30(�6K   $
��48,0q�6Y   � 5(      .+�5)      �� $��
320,30,0,0q�6   $��30��6!   $O��IC:\Users\norm\source\repos\Launcher1\Launcher1\Data\4_BULLETIN_BOARD2.gif��6,   $
��Left=�6   5*      �� 5+      $��Register��6   $��30(�5,      $��Center=�5-      $��0,30,0,0q�5.      $��Calibri)�5/      $	��200��50      
����������#2e3130$��40��53      55      � 56      .+�57      �� $��	70,0,0,10q�6   $��40��6    $H��BC:\Users\norm\source\repos\Launcher1\Launcher1\Data\4_F_KAFRA8.gif��6+   $
��Left=�6w   z�58      �� 59   	    �� ScaleX$ -1Q�6   5;      �� 5<      $��Settings��6   $��30(�5=      $��Center=�5>      $��0,0,0,0q�5?      $��Calibri)�5@      $	��200��5A      
����������#2e3130$��40��5D      5F      �� 5G      -   5        $��Start��5G      $��40(�5H      $��Center=�5I      $��0,0,0,0q�5J      $��Calibri)�5K      $	��300��5L      
����������#2e3130$��50��5O       �� 	IsDefault . 5P      5R      5S      �� 5T      -   5        $��Center=�5U      $	��240��5V      $��1080,545,0,0q�5W      $	��Top=�5X      $	��100��5Y      5Z      �� 5\      
�������$��2q�6   ���#2e3137$��0,100,900,0q�6H   $	��220��6]   $	��150��6j   $	 0.9Q�6v   �� 5]      '  !XamlAnimatedGif.AnimationBehavior   	SourceUri$B <C:\Users\norm\source\repos\Launcher1\Launcher1\Data\1031.gif?�6
   $��Center=�5^      $��40��5_      $��0,300,900,0q�5`      $	��Top=�5a      z�5b      �� 5c      $ -1Q�6   5e      �� 5f      $��Login��6
   
�������$��Calibri)�6-   $	��Top=�6B   $��Center=�6Z   $��20(�6w   $��0,300,730,0q�6�   $	��188��6�   $��48��6�   �� 5h      $B <C:\Users\norm\source\repos\Launcher1\Launcher1\Data\1031.gif?�6
   $��Center=�5i      $��40��5j      $��0,380,900,0q�5k      $	��Top=�5l      z�5m      �� 5n      $ -1Q�6   5p      �� 5q      $
��Char��6
   
�������$��Calibri)�6,   $	��Top=�6A   $��Center=�6Y   $��20(�6v   $��0,380,730,0q�6�   $	��188��6�   $��48��6�   �� 5t      $B <C:\Users\norm\source\repos\Launcher1\Launcher1\Data\1031.gif?�6
   $��Center=�5u      $��40��5v      $��0,460,900,0q�5w      $	��Top=�5x      z�5y      �� 5z      $ -1Q�6   5|      �� 5}      $	��Map��6
   
�������$��Calibri)�6+   $	��Top=�6@   $��Center=�6X   $��20(�6u   $��0,460,730,0q�6�   $	��188��6�   $��48��6�   5      5�      