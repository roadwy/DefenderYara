
rule Trojan_Win32_GuLoader_SIBM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SIBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {45 73 6f 74 68 79 72 6f 70 65 78 79 34 } //1 Esothyropexy4
		$a_03_1 = {56 f8 31 ff [0-04] 57 [0-05] ff d0 [0-08] e8 ?? ?? ?? ?? [0-08] 31 ff [0-10] bb ?? ?? ?? ?? [0-08] 81 f3 ?? ?? ?? ?? [0-30] 0b 1c 3a [0-08] 81 f3 ?? ?? ?? ?? [0-08] 09 1c 38 [0-0a] 83 c7 04 [0-05] 81 ff ?? ?? ?? ?? 75 ?? [0-07] ff d0 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}