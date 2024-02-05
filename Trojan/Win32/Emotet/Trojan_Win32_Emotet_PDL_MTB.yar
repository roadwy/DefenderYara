
rule Trojan_Win32_Emotet_PDL_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 90 01 01 8a 4c 15 90 01 01 30 08 90 00 } //01 00 
		$a_81_1 = {72 31 46 42 32 57 79 31 6a 72 62 43 48 61 51 4c 4e 73 6f 50 56 37 44 48 6f 70 56 63 58 6f 36 4c } //00 00 
	condition:
		any of ($a_*)
 
}