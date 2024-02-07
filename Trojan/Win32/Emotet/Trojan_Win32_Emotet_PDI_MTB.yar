
rule Trojan_Win32_Emotet_PDI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 84 34 90 01 04 0f b6 cb 03 c1 99 b9 90 01 04 f7 f9 8d 4c 24 90 01 01 83 c5 01 0f b6 94 14 90 01 04 30 55 90 00 } //01 00 
		$a_81_1 = {52 4d 72 45 69 59 67 33 52 32 37 74 42 4c 32 7a 66 52 30 71 4c 62 43 47 54 35 58 4d 7a 78 4c 59 48 6d 48 } //00 00  RMrEiYg3R27tBL2zfR0qLbCGT5XMzxLYHmH
	condition:
		any of ($a_*)
 
}