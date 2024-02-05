
rule Trojan_BAT_Meterpreter_MBN_MTB{
	meta:
		description = "Trojan:BAT/Meterpreter.MBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 } //01 00 
		$a_01_1 = {24 32 30 35 39 61 36 38 36 2d 33 66 35 30 2d 34 30 39 66 2d 39 39 31 63 2d 63 66 30 35 31 34 34 64 37 64 36 37 } //00 00 
	condition:
		any of ($a_*)
 
}