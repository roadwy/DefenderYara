
rule Trojan_BAT_Crysan_RDB_MTB{
	meta:
		description = "Trojan:BAT/Crysan.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 08 18 6f 19 00 00 0a 1f 10 28 1a 00 00 0a 6f 1b 00 00 0a 08 18 58 0c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}