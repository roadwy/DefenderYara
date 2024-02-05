
rule Trojan_Win64_Meterpreter_CCAH_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.CCAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {48 8b 45 e8 48 8d 55 18 48 89 54 24 28 48 8b 55 10 48 89 54 24 20 41 b9 00 00 00 00 41 b8 00 00 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 90 01 04 ff d0 85 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}