
rule Trojan_BAT_AsyncRat_AOV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.AOV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {18 16 15 28 90 01 03 0a 26 72 a3 00 00 70 16 16 15 28 90 01 03 0a 26 72 e7 00 00 70 16 16 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}