
rule Trojan_Win64_ValleyRat_ETL_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.ETL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 8b c0 4d 8d 49 01 99 41 ff c0 f7 f9 48 63 c2 0f b6 44 04 38 43 32 44 11 ff 42 88 84 0c 1f 05 00 00 41 81 f8 d8 08 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}