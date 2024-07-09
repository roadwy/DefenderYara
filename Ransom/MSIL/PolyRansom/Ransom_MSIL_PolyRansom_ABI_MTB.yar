
rule Ransom_MSIL_PolyRansom_ABI_MTB{
	meta:
		description = "Ransom:MSIL/PolyRansom.ABI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {08 09 6f 35 ?? ?? 0a 07 6f 36 ?? ?? 0a 08 6f 37 ?? ?? 0a 09 6f 38 ?? ?? 0a 13 04 de 1a } //2
		$a_01_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //1 CreateInstance
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 } //1 GetTempPath
		$a_01_3 = {47 65 74 44 65 63 6f 64 65 72 53 74 72 65 61 6d } //1 GetDecoderStream
		$a_01_4 = {43 6d 52 63 63 53 65 72 76 69 63 65 } //1 CmRccService
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}