
rule Trojan_Win32_SpyStealer_V_MTB{
	meta:
		description = "Trojan:Win32/SpyStealer.V!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {56 69 72 74 c7 05 90 01 04 75 61 6c 50 c7 05 90 01 04 72 6f 74 65 66 c7 05 90 01 04 63 74 c6 05 90 01 05 ff 15 3c 10 40 00 90 00 } //0a 00 
		$a_02_1 = {50 ff 75 fc ff 35 c4 0a 91 00 ff 35 24 50 90 01 02 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}