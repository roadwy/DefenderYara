
rule Trojan_BAT_ConvertRat_AMTB{
	meta:
		description = "Trojan:BAT/ConvertRat!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_80_0 = {2d 2d 68 69 64 65 2d 63 72 61 73 68 2d 72 65 73 74 6f 72 65 2d 62 75 62 62 6c 65 20 2d 2d 72 65 73 74 6f 72 65 2d 6c 61 73 74 2d 73 65 73 73 69 6f 6e } //--hide-crash-restore-bubble --restore-last-session  2
		$a_80_1 = {45 78 63 65 70 74 69 6f 6e 20 77 68 69 6c 65 20 63 72 65 61 74 69 6e 67 20 73 68 6f 72 74 63 75 74 2e 20 20 20 55 32 39 6d 64 48 64 68 63 6d 56 63 54 57 6c 6a 63 6d 39 7a 62 32 5a 30 58 46 64 70 62 6d 52 76 64 33 4e 63 51 33 56 79 63 6d 56 75 64 46 5a 6c 63 6e 4e 70 62 32 35 63 56 57 35 70 62 6e 4e 30 59 57 78 73 58 41 3d 3d } //Exception while creating shortcut.   U29mdHdhcmVcTWljcm9zb2Z0XFdpbmRvd3NcQ3VycmVudFZlcnNpb25cVW5pbnN0YWxsXA==  2
		$a_80_2 = {70 61 67 65 73 2f 63 6f 6e 66 69 72 6d 70 61 67 65 2e 78 61 6d 6c } //pages/confirmpage.xaml  1
		$a_80_3 = {70 61 67 65 73 2f 66 69 72 73 74 70 61 67 65 2e 78 61 6d 6c } //pages/firstpage.xaml  1
		$a_80_4 = {70 61 67 65 73 2f 6d 61 69 6e 77 69 6e 64 6f 77 2e 78 61 6d 6c } //pages/mainwindow.xaml  1
		$a_80_5 = {68 74 74 70 73 3a 2f 2f 70 73 6f 74 69 6d 69 6d 2e 63 6f 6d 2f 6e 65 77 } //https://psotimim.com/new  4
		$a_80_6 = {45 6e 63 6f 64 65 4a 73 6f 6e } //EncodeJson  1
		$a_80_7 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 } //get_UserName  1
		$a_80_8 = {52 65 6c 61 75 6e 63 68 43 68 72 6f 6d 65 } //RelaunchChrome  1
		$a_80_9 = {53 68 75 74 64 6f 77 6e 43 68 72 6f 6d 65 } //ShutdownChrome  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*4+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1) >=10
 
}