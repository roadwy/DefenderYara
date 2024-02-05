
rule Trojan_Win32_Emotet_PDD_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PDD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 90 01 01 83 4d 90 01 01 ff 8a 8c 15 90 01 04 30 08 90 00 } //01 00 
		$a_81_1 = {38 78 38 4e 46 72 44 62 6c 67 56 64 7a 34 61 57 37 64 75 47 4e 5a 66 4f 43 77 38 56 30 39 51 47 4d } //00 00 
	condition:
		any of ($a_*)
 
}