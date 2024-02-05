
rule Trojan_BAT_DarkCloudStealer_A_MTB{
	meta:
		description = "Trojan:BAT/DarkCloudStealer.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {00 00 01 25 16 1f 90 01 01 9d 6f 90 01 02 00 0a 0b 90 09 05 00 00 0a 17 8d 90 00 } //02 00 
		$a_03_1 = {00 00 01 25 16 1f 90 01 01 9d 6f 90 01 02 00 0a 0d 90 09 05 00 00 04 17 8d 90 00 } //02 00 
		$a_03_2 = {08 06 07 06 9a 1f 10 28 90 01 02 00 0a 9c 06 17 d6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}