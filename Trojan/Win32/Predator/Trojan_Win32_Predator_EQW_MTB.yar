
rule Trojan_Win32_Predator_EQW_MTB{
	meta:
		description = "Trojan:Win32/Predator.EQW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_02_0 = {8a 4c 01 15 8b 35 ?? ?? ?? ?? 88 0c 06 8b 0d ?? ?? ?? ?? 81 f9 03 02 00 00 75 06 } //10
		$a_80_1 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  5
		$a_80_2 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  5
		$a_00_3 = {81 fe 2b ac 01 00 7f 09 46 81 fe ba 2d bc 1e 7c d2 } //5
	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*5+(#a_80_2  & 1)*5+(#a_00_3  & 1)*5) >=25
 
}