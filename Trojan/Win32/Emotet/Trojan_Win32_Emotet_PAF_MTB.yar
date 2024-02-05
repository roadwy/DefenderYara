
rule Trojan_Win32_Emotet_PAF_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b da 03 d9 ff 15 90 01 04 8a 14 33 8a 44 24 90 01 01 8b 4c 24 90 01 01 02 d0 8b 44 24 90 01 01 32 14 01 88 10 40 89 44 24 90 01 01 ff 4c 24 90 01 01 75 90 00 } //01 00 
		$a_01_1 = {64 00 72 00 74 00 66 00 66 00 44 00 57 00 45 00 55 00 46 00 45 00 55 00 46 00 55 00 57 00 45 00 47 00 46 00 55 00 59 00 42 00 47 00 } //00 00 
	condition:
		any of ($a_*)
 
}