
rule Trojan_BAT_AsyncRAT_MBBV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.MBBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {08 14 20 d6 00 00 00 28 90 01 01 00 00 06 17 8d 90 01 01 00 00 01 25 16 7e 0a 00 00 04 a2 25 0d 14 14 17 8d 90 01 01 00 00 01 25 16 17 9c 25 13 04 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}