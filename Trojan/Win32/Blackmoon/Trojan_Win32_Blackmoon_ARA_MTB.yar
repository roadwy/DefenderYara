
rule Trojan_Win32_Blackmoon_ARA_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.ARA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 2a 20 2f 66 } //02 00  cmd /c schtasks /delete /tn * /f
		$a_01_1 = {74 72 61 70 63 65 61 70 65 74 2e 65 78 65 } //02 00  trapceapet.exe
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 3a } //00 00  BlackMoon RunTime Error:
	condition:
		any of ($a_*)
 
}