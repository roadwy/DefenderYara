
rule Trojan_Win32_Emotet_PDQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8a 03 8d 4c 24 90 01 01 c7 84 24 90 01 04 ff ff ff ff 8a 94 14 90 01 04 32 c2 88 03 90 09 05 00 b9 90 00 } //01 00 
		$a_81_1 = {75 39 4a 72 39 77 4f 6f 4c 79 45 6a 71 49 49 37 48 6d 37 66 6b 74 61 65 71 48 72 41 38 49 6f 34 54 30 57 38 66 34 70 58 } //00 00 
	condition:
		any of ($a_*)
 
}