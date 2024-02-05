
rule Trojan_Win32_Emotet_DSX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 44 34 90 01 01 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 83 c5 01 0f b6 54 14 90 01 01 30 55 90 00 } //01 00 
		$a_81_1 = {69 62 56 30 37 6b 38 4f 76 4c 49 63 33 43 43 39 74 51 41 54 6e 31 30 6e 7a 58 48 53 37 61 65 55 33 79 6a 55 50 36 68 6b 37 79 30 4f } //00 00 
	condition:
		any of ($a_*)
 
}