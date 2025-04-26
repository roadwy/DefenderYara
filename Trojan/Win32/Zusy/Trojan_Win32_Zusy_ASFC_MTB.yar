
rule Trojan_Win32_Zusy_ASFC_MTB{
	meta:
		description = "Trojan:Win32/Zusy.ASFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 41 75 64 69 6f 44 65 63 6f 64 65 72 00 43 72 65 61 74 65 56 69 64 65 6f 44 65 63 6f 64 65 72 00 44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 00 44 6c 6c 45 6e 74 72 79 } //5 牃慥整畁楤䑯捥摯牥䌀敲瑡噥摩潥敄潣敤r汄䍬湡湕潬摡潎w汄䕬瑮祲
	condition:
		((#a_01_0  & 1)*5) >=5
 
}