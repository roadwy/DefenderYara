
rule Trojan_Win32_IcedId_DAJ_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 14 b0 a9 2a 05 90 01 04 8b 74 24 10 2a c4 02 c8 89 1d 90 01 04 8b 44 24 28 89 35 90 01 04 8b 38 81 c7 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}