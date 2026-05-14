
rule Trojan_Win32_ValleyRat_A_AMTB{
	meta:
		description = "Trojan:Win32/ValleyRat.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 22 4d 69 63 72 6f 53 74 61 72 74 41 70 70 22 20 2f 74 72 20 22 25 73 22 20 2f 73 63 20 6f 6e 6c 6f 67 6f 6e 20 2f 72 6c 20 68 69 67 68 65 73 74 20 2f 66 } //schtasks /create /tn "MicroStartApp" /tr "%s" /sc onlogon /rl highest /f  3
		$a_80_1 = {43 3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 56 65 72 73 69 6f 6e 5c 67 6c 69 62 63 56 65 72 73 69 6f 6e 5c 25 73 2e 65 78 65 } //C:\Users\AdministratorVersion\glibcVersion\%s.exe  3
		$a_80_2 = {41 64 64 2d 4d 70 50 72 65 66 65 72 65 6e 63 65 20 2d 45 78 63 6c 75 73 69 6f 6e 50 61 74 68 20 25 73 } //Add-MpPreference -ExclusionPath %s  2
		$a_80_3 = {70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 } //powershell.exe  1
		$a_80_4 = {25 53 23 5b 6b } //%S#[k  1
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*2+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=10
 
}