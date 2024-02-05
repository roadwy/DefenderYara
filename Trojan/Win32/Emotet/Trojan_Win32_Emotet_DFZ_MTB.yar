
rule Trojan_Win32_Emotet_DFZ_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DFZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 14 8a 8c 15 90 01 04 30 08 90 00 } //01 00 
		$a_81_1 = {6c 54 6b 6f 4e 6b 46 71 6c 79 72 6c 64 38 74 43 79 36 4b 55 6d 6b 39 44 5a 35 64 57 69 34 35 37 59 6d 79 46 72 } //00 00 
	condition:
		any of ($a_*)
 
}