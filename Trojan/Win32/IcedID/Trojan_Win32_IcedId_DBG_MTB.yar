
rule Trojan_Win32_IcedId_DBG_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 01 6a 00 6a 00 8d 55 90 01 01 52 ff 15 90 01 04 85 c0 75 3f 6a 08 6a 01 6a 00 6a 00 8d 45 90 1b 00 50 ff 15 90 1b 01 85 c0 90 00 } //01 00 
		$a_81_1 = {6a 48 39 7b 50 7c 6e 57 4b 42 70 50 50 25 4a } //00 00  jH9{P|nWKBpPP%J
	condition:
		any of ($a_*)
 
}