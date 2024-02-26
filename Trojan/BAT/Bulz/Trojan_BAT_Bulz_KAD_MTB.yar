
rule Trojan_BAT_Bulz_KAD_MTB{
	meta:
		description = "Trojan:BAT/Bulz.KAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 1c 06 1c 95 07 1c 95 58 20 90 01 04 5a 9e 06 1d 06 1d 95 07 1d 95 61 20 90 01 04 58 9e 11 0b 90 00 } //05 00 
		$a_01_1 = {3b 48 6b ed 42 19 ab 06 56 e3 a8 f5 98 a3 cd 7f 10 ee 0c b4 74 27 46 f7 49 56 db d2 51 4b b2 } //00 00 
	condition:
		any of ($a_*)
 
}