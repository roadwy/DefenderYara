
rule Trojan_BAT_Injector_CDB_MTB{
	meta:
		description = "Trojan:BAT/Injector.CDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {6a 5f 69 95 61 d2 9c 00 11 06 17 58 13 06 11 06 11 09 13 0b 11 0b 31 a3 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}