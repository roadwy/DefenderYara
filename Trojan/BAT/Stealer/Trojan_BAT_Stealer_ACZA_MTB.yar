
rule Trojan_BAT_Stealer_ACZA_MTB{
	meta:
		description = "Trojan:BAT/Stealer.ACZA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0c 08 28 ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 6f ?? 00 00 0a 00 11 04 18 6f ?? 00 00 0a 00 11 04 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 13 05 02 } //5
		$a_00_1 = {48 00 35 00 38 00 34 00 35 00 39 00 37 00 42 00 38 00 47 00 34 00 37 00 44 00 32 00 48 00 5a 00 43 00 35 00 4b 00 53 00 46 00 37 00 } //1 H584597B8G47D2HZC5KSF7
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*1) >=6
 
}