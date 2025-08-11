
rule Trojan_BAT_Crysan_EAFS_MTB{
	meta:
		description = "Trojan:BAT/Crysan.EAFS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 23 00 00 00 00 00 00 f0 3f 11 04 6c 23 00 00 00 00 00 00 24 40 5b 28 cd 00 00 0a 23 7b 14 ae 47 e1 7a 94 3f 5a 58 5a 0c 11 04 17 d6 13 04 11 04 09 31 cc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}