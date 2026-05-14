
rule Trojan_BAT_Lazy_VD_MTB{
	meta:
		description = "Trojan:BAT/Lazy.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 70 09 00 70 28 8d 00 00 0a 11 05 28 b0 00 00 0a 13 0a 11 0a 28 b1 00 00 0a 26 11 0a 12 01 7b 19 00 00 04 72 80 09 00 70 28 b2 00 00 0a 13 0b 11 0b 28 32 00 00 0a 2d 32 } //5
		$a_81_1 = {30 62 39 39 30 36 39 65 2d 33 62 38 37 2d 34 35 66 38 2d 62 35 32 31 2d 32 35 33 65 65 39 34 36 34 66 38 34 } //5 0b99069e-3b87-45f8-b521-253ee9464f84
	condition:
		((#a_01_0  & 1)*5+(#a_81_1  & 1)*5) >=10
 
}