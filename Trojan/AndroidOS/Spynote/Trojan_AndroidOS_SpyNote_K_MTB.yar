
rule Trojan_AndroidOS_SpyNote_K_MTB{
	meta:
		description = "Trojan:AndroidOS/SpyNote.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 0a 3d 00 77 00 bc 18 00 00 0c 20 14 23 8b a1 1a 00 77 00 e7 1d 00 00 0c 1f 77 01 bb 18 1f 00 0a 1f 97 23 23 1f 14 21 59 91 1a 00 77 00 f4 1f 00 00 0c 1f 77 01 bb 18 1f 00 0a 1f 97 21 21 1f 14 22 11 9b 1a 00 77 00 e4 1e 00 00 0c 1f 77 01 bb 18 1f 00 0a 1f 97 22 22 1f 77 04 ba 18 20 00 0c 20 08 00 20 00 12 31 71 20 e8 20 10 00 0a 01 12 02 13 03 31 00 12 14 33 31 1a 00 22 01 56 03 71 10 c4 20 0a 00 0c 05 70 20 5d 1a 51 00 5b a1 d0 0b 71 10 ab 1c 0a 00 0c 01 71 10 bb 20 01 00 0a 01 38 01 03 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}