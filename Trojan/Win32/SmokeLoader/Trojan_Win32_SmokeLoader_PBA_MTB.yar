
rule Trojan_Win32_SmokeLoader_PBA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 14 33 44 24 10 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 2b f0 8b ce c1 e1 04 89 44 24 14 89 4c 24 10 8b 44 24 2c 01 44 24 10 8b d6 c1 ea 05 } //1
		$a_03_1 = {50 68 c4 3f 40 00 ff 15 ?? ?? ?? ?? 8b 4c 24 14 8b 44 24 10 33 cf 33 c1 2b e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}