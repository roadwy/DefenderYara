
rule Trojan_BAT_ZgRat_MA_MTB{
	meta:
		description = "Trojan:BAT/ZgRat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7e 97 00 00 04 20 2e 01 00 00 7e 97 00 00 04 20 2e 01 00 00 93 04 5a 20 d2 00 00 00 5f 9d } //00 00 
	condition:
		any of ($a_*)
 
}