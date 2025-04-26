
rule Trojan_Win32_StealC_IDL_MTB{
	meta:
		description = "Trojan:Win32/StealC.IDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ff 89 74 24 18 89 3d ?? ?? ?? ?? 8b 44 24 18 01 05 c8 2c ba 00 a1 ?? ?? ?? ?? 89 44 24 28 89 7c 24 18 8b 44 24 28 01 44 24 18 8b 44 24 10 33 44 24 18 89 44 24 18 8b 4c 24 18 } //1
		$a_03_1 = {33 c6 89 44 24 10 8b 44 24 18 31 44 24 10 a1 ?? ?? ?? ?? 2b 5c 24 10 3d ?? ?? ?? ?? 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}