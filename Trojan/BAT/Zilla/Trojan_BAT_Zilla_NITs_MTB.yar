
rule Trojan_BAT_Zilla_NITs_MTB{
	meta:
		description = "Trojan:BAT/Zilla.NITs!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {3a 32 00 00 00 28 ?? 00 00 06 3a 28 00 00 00 28 ?? 00 00 06 3a 1e 00 00 00 28 ?? 00 00 06 3a 14 00 00 00 28 ?? 00 00 06 3a 0a 00 00 00 28 ?? 00 00 06 39 06 00 00 00 16 28 ?? 00 00 0a 2a } //2
		$a_01_1 = {52 75 6e 41 6e 74 69 41 6e 61 6c 79 73 69 73 } //1 RunAntiAnalysis
		$a_01_2 = {44 65 66 65 6e 64 65 72 } //1 Defender
		$a_01_3 = {41 6e 74 69 56 69 72 74 75 61 6c } //1 AntiVirtual
		$a_01_4 = {41 6e 74 69 50 72 6f 63 65 73 73 } //1 AntiProcess
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}