
rule Trojan_Win64_ClipBanker_BI_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 22 41 80 f0 22 41 80 f1 22 88 44 24 21 33 db 44 88 44 24 24 b1 4e 44 88 4c 24 25 80 f1 22 88 5c 24 28 b2 4b 88 4c 24 22 80 f2 22 48 8d 44 24 21 41 b2 47 88 54 24 23 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}