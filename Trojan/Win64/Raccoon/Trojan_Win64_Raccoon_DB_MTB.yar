
rule Trojan_Win64_Raccoon_DB_MTB{
	meta:
		description = "Trojan:Win64/Raccoon.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d0 05 4f d4 a4 db 35 be 98 68 c9 c1 c0 f6 66 9d e9 [0-04] 41 0f b6 04 08 88 01 48 8d 49 01 48 83 ea 01 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}