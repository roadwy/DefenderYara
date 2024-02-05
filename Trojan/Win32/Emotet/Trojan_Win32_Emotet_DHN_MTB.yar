
rule Trojan_Win32_Emotet_DHN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 ec 0c 53 56 57 a1 90 01 04 33 c5 50 8d 45 f4 64 a3 00 00 00 00 89 65 f0 8b f9 89 7d ec 8b 45 08 8b f0 83 ce 0f 90 00 } //01 00 
		$a_00_1 = {ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 6a 00 6a 00 6a 00 6a 00 ff d6 } //01 00 
		$a_00_2 = {30 54 72 53 30 61 73 24 35 57 76 50 61 6a 7e } //00 00 
	condition:
		any of ($a_*)
 
}