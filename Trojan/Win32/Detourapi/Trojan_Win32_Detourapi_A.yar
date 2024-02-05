
rule Trojan_Win32_Detourapi_A{
	meta:
		description = "Trojan:Win32/Detourapi.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a ff ff 15 90 01 02 40 00 c6 05 90 01 02 40 00 68 c6 05 90 01 02 40 00 c3 c7 05 90 01 02 40 00 87 27 40 00 8d 55 fc 52 6a 06 90 00 } //01 00 
		$a_01_1 = {ac 08 c0 74 07 34 9b 90 aa 90 e2 f4 } //00 00 
	condition:
		any of ($a_*)
 
}