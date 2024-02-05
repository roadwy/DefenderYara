
rule Trojan_Win32_Zenpak_DEA_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8b 85 90 01 04 40 83 c4 04 89 85 90 1b 01 0f b6 94 15 90 01 04 30 50 ff 90 00 } //01 00 
		$a_81_1 = {52 6c 34 4a 33 63 4d 74 46 72 69 45 76 38 63 59 4e 4d 64 68 72 35 33 74 76 44 72 53 58 64 4c 57 31 36 6c 68 36 57 77 } //00 00 
	condition:
		any of ($a_*)
 
}