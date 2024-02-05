
rule Trojan_Win32_Drolnux_RF_MTB{
	meta:
		description = "Trojan:Win32/Drolnux.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff 8b 44 24 20 09 c0 0f 85 72 01 00 00 8b 43 3c 8d 74 24 3c c7 44 24 08 02 00 00 00 31 ff 89 74 24 0c 01 d8 89 c6 89 44 24 1c 8b 40 54 89 1c 24 } //00 00 
	condition:
		any of ($a_*)
 
}