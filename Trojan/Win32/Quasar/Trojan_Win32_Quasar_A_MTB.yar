
rule Trojan_Win32_Quasar_A_MTB{
	meta:
		description = "Trojan:Win32/Quasar.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 00 74 00 61 00 72 00 74 00 20 00 6d 00 61 00 69 00 6c 00 74 00 6f 00 3a 00 66 00 72 00 65 00 64 00 69 00 73 00 6f 00 66 00 74 00 40 00 62 00 6f 00 6c 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72 00 } //1 start mailto:fredisoft@bol.com.br
		$a_01_1 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 50 00 61 00 74 00 68 00 20 00 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 } //1 cmd.exe /c powershell Add-MpPreference -ExclusionPath C:\Users
		$a_81_2 = {6b 69 63 6d 68 64 6a 6f 67 } //1 kicmhdjog
		$a_81_3 = {6e 6f 6d 63 6f 6d 70 } //1 nomcomp
		$a_81_4 = {66 6d 7a 66 74 70 6c 66 6b 66 64 67 75 66 6a 68 73 77 61 69 61 62 77 6d 75 63 62 76 6c 76 6f } //1 fmzftplfkfdgufjhswaiabwmucbvlvo
		$a_81_5 = {6f 6d 68 72 6d 69 6f 74 6c } //1 omhrmiotl
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}