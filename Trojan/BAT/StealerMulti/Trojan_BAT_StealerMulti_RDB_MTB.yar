
rule Trojan_BAT_StealerMulti_RDB_MTB{
	meta:
		description = "Trojan:BAT/StealerMulti.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8e 69 5d 91 03 11 04 91 61 d2 9c } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}