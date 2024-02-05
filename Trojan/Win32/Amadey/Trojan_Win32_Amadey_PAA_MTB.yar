
rule Trojan_Win32_Amadey_PAA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.PAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 6d 58 6a 73 66 a3 90 01 04 58 6a 33 66 a3 90 01 04 58 6a 67 66 a3 90 01 04 33 c0 66 a3 90 01 04 58 6a 64 66 a3 90 01 04 58 6a 6d 66 a3 90 01 04 58 6a 6c 66 a3 90 01 04 58 6a 2e 66 a3 90 01 04 58 6a 6c 66 a3 90 01 04 58 6a 32 66 a3 90 01 04 58 6a 69 66 a3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}