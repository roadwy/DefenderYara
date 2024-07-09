
rule Trojan_Win64_ShellcodeRunner_DX_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 c2 89 d0 c1 e0 02 01 d0 01 c0 01 d0 29 c1 89 ca 48 63 c2 0f b6 44 05 ?? 44 31 c0 89 c1 8b 45 fc 48 98 48 8d 15 [0-04] 88 0c 10 83 45 fc 01 8b 45 fc 3d fd 01 00 00 76 } //1
		$a_03_1 = {29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 48 63 c2 0f b6 44 05 ?? 44 31 c0 89 c1 8b 45 fc 48 98 48 8d 15 [0-04] 88 0c 10 83 45 fc 01 8b 45 fc 3d fd 01 00 00 76 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}