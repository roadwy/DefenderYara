
rule Trojan_Win64_ClipBanker_NJB_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.NJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {44 69 61 6d 6f 74 72 69 78 } //2 Diamotrix
		$a_81_1 = {62 62 69 74 63 6f 69 6e 63 61 73 68 } //1 bbitcoincash
		$a_03_2 = {4c 8b c3 33 d2 48 8b c6 48 f7 77 ?? 42 8a 04 0a 32 04 31 41 88 04 30 48 ff c6 48 3b 74 24 } //1
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}