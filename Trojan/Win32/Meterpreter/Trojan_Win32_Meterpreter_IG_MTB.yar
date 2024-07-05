
rule Trojan_Win32_Meterpreter_IG_MTB{
	meta:
		description = "Trojan:Win32/Meterpreter.IG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0f b6 db 8a 94 1d 90 01 04 88 94 05 90 01 04 89 fa 88 94 1d 90 01 04 02 94 05 90 01 04 0f b6 d2 8a 94 15 90 01 04 30 11 41 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}