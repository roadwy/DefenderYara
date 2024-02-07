
rule Trojan_Win32_Emotet_DSN_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DSN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 06 0f b6 d3 03 c2 99 8b f1 f7 fe 8b 45 90 01 01 8a 54 15 90 01 01 30 10 90 00 } //01 00 
		$a_81_1 = {36 4b 66 63 45 6c 46 34 74 49 4b 76 75 75 57 44 77 4d 6e 7a 33 64 65 32 64 67 68 57 53 76 63 45 68 54 39 36 } //00 00  6KfcElF4tIKvuuWDwMnz3de2dghWSvcEhT96
	condition:
		any of ($a_*)
 
}