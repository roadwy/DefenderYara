
rule Trojan_Win32_IcedId_DAT_MTB{
	meta:
		description = "Trojan:Win32/IcedId.DAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {53 6a 01 53 8d 44 24 90 01 01 53 50 89 5c 24 90 01 01 ff 15 90 01 04 85 c0 75 3a 6a 08 6a 01 53 8d 4c 24 90 1b 00 53 51 ff 15 90 1b 02 85 c0 90 00 } //01 00 
		$a_81_1 = {56 56 58 4e 48 5a 45 66 70 37 31 6b 46 6c 47 55 58 76 35 64 75 36 30 43 35 39 39 72 67 61 6d 53 42 79 53 73 6a 58 41 } //00 00 
	condition:
		any of ($a_*)
 
}