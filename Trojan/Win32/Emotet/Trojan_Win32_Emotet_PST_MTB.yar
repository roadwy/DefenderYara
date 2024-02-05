
rule Trojan_Win32_Emotet_PST_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {81 e1 ff 00 00 00 03 c1 b9 90 01 04 99 f7 f9 8a 03 8a 94 14 90 01 04 32 c2 88 03 90 09 07 00 8a 84 34 90 00 } //01 00 
		$a_81_1 = {6d 6e 35 6f 51 46 65 79 70 6e 61 6f 4e 75 56 45 4a 6d 35 50 6c 74 6a 74 30 6d 61 66 61 38 41 77 4e 31 65 71 78 } //00 00 
	condition:
		any of ($a_*)
 
}