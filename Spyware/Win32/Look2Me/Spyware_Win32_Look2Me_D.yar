
rule Spyware_Win32_Look2Me_D{
	meta:
		description = "Spyware:Win32/Look2Me.D,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 65 72 3c 62 3e } //1 Installer<b>
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 6f 6f 6b 32 6d 65 2e 63 6f 6d } //1 http://www.look2me.com
		$a_01_2 = {3c 2f 66 6f 72 6d 3e 3c 2f 64 69 76 3e 3c 73 63 72 69 70 74 20 6c 61 6e 67 75 61 67 65 3d 27 6a 61 76 61 73 63 72 69 70 74 27 3e } //1 </form></div><script language='javascript'>
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4c 6f 6f 6b 32 4d 65 } //1 Software\Look2Me
		$a_01_4 = {4f 6e 54 6f 6f 6c 42 61 72 } //1 OnToolBar
		$a_01_5 = {6d 65 74 68 6f 64 3d 50 4f 53 54 3e 3c 69 6e 70 75 74 20 74 79 70 65 3d 27 68 69 64 64 65 6e 27 20 6e 61 6d 65 3d 27 69 64 27 } //1 method=POST><input type='hidden' name='id'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}