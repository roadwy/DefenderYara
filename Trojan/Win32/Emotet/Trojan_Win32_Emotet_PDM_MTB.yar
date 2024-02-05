
rule Trojan_Win32_Emotet_PDM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8d 4c 24 90 01 01 83 c5 01 0f b6 94 14 90 01 04 30 55 90 00 } //01 00 
		$a_81_1 = {64 34 35 77 68 30 59 44 38 49 32 49 75 35 67 70 6c 76 6c 4d 65 50 54 54 57 63 34 33 70 4b 61 33 6f 59 4b 65 4a } //00 00 
	condition:
		any of ($a_*)
 
}