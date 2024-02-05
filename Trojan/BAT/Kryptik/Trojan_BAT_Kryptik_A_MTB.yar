
rule Trojan_BAT_Kryptik_A_MTB{
	meta:
		description = "Trojan:BAT/Kryptik.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {02 7e 5a 00 00 04 25 2d 17 26 7e 59 00 00 04 fe 06 2c 00 00 06 73 ab 00 00 0a 25 80 5a 00 00 04 7d 56 00 00 04 02 7e 5b 00 00 04 25 2d 17 26 7e 59 00 00 04 fe 06 2d 00 00 06 73 ac 00 00 0a 25 80 5b } //01 00 
		$a_01_1 = {71 61 6b 65 52 6b 70 71 } //01 00 
		$a_01_2 = {74 61 7a 63 49 6d 6a 35 32 } //00 00 
	condition:
		any of ($a_*)
 
}