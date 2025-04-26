
rule Trojan_BAT_ClipBanker_RDG_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.RDG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {32 36 62 39 33 31 39 30 2d 32 39 64 30 2d 34 62 65 66 2d 38 33 34 61 2d 62 35 35 31 36 39 36 38 33 64 31 65 } //1 26b93190-29d0-4bef-834a-b55169683d1e
		$a_01_1 = {73 73 73 63 63 } //1 ssscc
		$a_01_2 = {77 35 65 74 77 7a 69 30 64 65 73 } //1 w5etwzi0des
		$a_01_3 = {5a 00 34 00 71 00 34 00 62 00 55 00 56 00 34 00 47 00 32 00 61 00 32 00 41 00 6b 00 53 00 70 00 44 00 63 00 } //1 Z4q4bUV4G2a2AkSpDc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}