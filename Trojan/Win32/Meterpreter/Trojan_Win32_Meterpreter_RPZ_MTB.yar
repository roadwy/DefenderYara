
rule Trojan_Win32_Meterpreter_RPZ_MTB{
	meta:
		description = "Trojan:Win32/Meterpreter.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 5b 61 59 5a 51 ff e0 58 5f 5a 8b 12 e9 } //00 00 
	condition:
		any of ($a_*)
 
}