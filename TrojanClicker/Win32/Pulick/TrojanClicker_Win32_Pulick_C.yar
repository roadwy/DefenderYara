
rule TrojanClicker_Win32_Pulick_C{
	meta:
		description = "TrojanClicker:Win32/Pulick.C,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 0a 00 00 "
		
	strings :
		$a_01_0 = {77 69 6e 64 6f 77 2e 6f 6e 62 65 66 6f 72 65 75 6e 6c 6f 61 64 3d 6e 75 6c 6c 3b 77 69 6e 64 6f 77 2e 73 68 6f 77 4d 6f 64 61 6c 44 69 61 6c 6f 67 3d 6e 75 6c 6c 3b 77 69 6e 64 6f 77 2e 63 6f 6e 66 69 72 6d 3d 6e 75 6c 6c 3b 77 69 6e 64 6f 77 2e 6f 70 65 6e 3d 6e 75 6c 6c 3b 64 6f 63 75 6d 65 6e 74 2e 62 6f 64 79 2e 6f 6e 63 6c 69 63 6b 3d 6e 75 6c 6c 3b } //3 window.onbeforeunload=null;window.showModalDialog=null;window.confirm=null;window.open=null;document.body.onclick=null;
		$a_01_1 = {58 52 58 65 58 66 58 65 58 72 58 65 58 72 58 3a 58 } //3 XRXeXfXeXrXeXrX:X
		$a_01_2 = {6d 32 72 58 66 58 } //1 m2rXfX
		$a_01_3 = {63 6c 69 63 6b 2e 68 74 6d 6c } //1 click.html
		$a_01_4 = {64 6f 75 62 6c 65 69 6d 70 } //1 doubleimp
		$a_01_5 = {6d 32 72 66 2e 63 6f 6d } //1 m2rf.com
		$a_01_6 = {66 61 67 74 2e 63 6f 6d } //1 fagt.com
		$a_01_7 = {65 78 6f 63 6c 69 63 6b } //1 exoclick
		$a_01_8 = {65 72 6f 2d 61 64 76 } //1 ero-adv
		$a_01_9 = {61 64 75 6c 74 61 64 77 6f 72 6c 64 } //1 adultadworld
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1) >=9
 
}