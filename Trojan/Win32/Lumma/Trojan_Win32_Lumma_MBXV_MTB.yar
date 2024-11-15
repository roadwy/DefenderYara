
rule Trojan_Win32_Lumma_MBXV_MTB{
	meta:
		description = "Trojan:Win32/Lumma.MBXV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 89 5c 24 44 33 c9 8b c1 88 4c 0c 4c 99 f7 bc 24 ?? ?? 00 00 8a 04 32 88 84 0c ?? ?? 00 00 41 3b cd 7c e3 } //2
		$a_01_1 = {5a 38 31 78 62 79 75 41 75 61 00 00 51 77 72 75 78 41 41 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}