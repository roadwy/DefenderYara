
rule Trojan_Win32_GuLoader_SIBM3_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {50 00 41 00 52 00 41 00 4c 00 4c 00 45 00 4c 00 49 00 5a 00 49 00 4e 00 47 00 } //1 PARALLELIZING
		$a_03_1 = {e0 81 34 17 ?? ?? ?? ?? [0-30] 83 c2 04 [0-30] 81 fa ?? ?? ?? ?? 0f 85 ?? ?? ?? ?? [0-30] ff e7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}