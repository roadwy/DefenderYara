
rule Trojan_Win32_Zbot_VHO_MTB{
	meta:
		description = "Trojan:Win32/Zbot.VHO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 70 8b 45 60 8b 40 60 8b d7 33 c9 83 e7 fc c1 e2 02 41 89 5d 4c 83 ff 04 76 0e 31 04 8e 8b 7d 70 41 c1 ef 02 3b cf 72 f2 } //10
		$a_80_1 = {6b 69 6c 66 31 2e 65 78 65 } //kilf1.exe  1
		$a_80_2 = {62 75 64 68 61 2e 65 78 65 } //budha.exe  1
	condition:
		((#a_01_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=12
 
}