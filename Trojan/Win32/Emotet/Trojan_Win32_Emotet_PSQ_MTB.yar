
rule Trojan_Win32_Emotet_PSQ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PSQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 84 05 90 01 04 03 c1 b9 90 01 04 99 f7 f9 8b 45 90 01 01 8a 8c 15 90 01 04 30 08 90 00 } //01 00 
		$a_81_1 = {41 71 4e 57 5a 52 50 6e 38 4b 50 44 78 38 59 56 36 41 44 6e 75 54 69 73 30 4d 32 5a 6d 49 37 31 56 6e 6e 51 38 72 77 55 67 } //00 00 
	condition:
		any of ($a_*)
 
}