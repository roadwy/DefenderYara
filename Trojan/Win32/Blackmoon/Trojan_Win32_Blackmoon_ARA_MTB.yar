
rule Trojan_Win32_Blackmoon_ARA_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 39 c1 ef 02 c1 e2 06 8d 54 17 01 8b f8 41 2b fa 8b da c1 ee 05 4e 8a 17 88 10 8a 57 01 88 50 01 83 c0 02 83 c7 02 8a 17 88 10 40 47 4e 75 f7 } //2
		$a_00_1 = {63 6f 64 65 72 70 75 62 } //1 coderpub
	condition:
		((#a_01_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}
rule Trojan_Win32_Blackmoon_ARA_MTB_2{
	meta:
		description = "Trojan:Win32/Blackmoon.ARA!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6d 64 20 2f 63 20 73 63 68 74 61 73 6b 73 20 2f 64 65 6c 65 74 65 20 2f 74 6e 20 2a 20 2f 66 } //2 cmd /c schtasks /delete /tn * /f
		$a_01_1 = {74 72 61 70 63 65 61 70 65 74 2e 65 78 65 } //2 trapceapet.exe
		$a_01_2 = {42 6c 61 63 6b 4d 6f 6f 6e 20 52 75 6e 54 69 6d 65 20 45 72 72 6f 72 3a } //2 BlackMoon RunTime Error:
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}