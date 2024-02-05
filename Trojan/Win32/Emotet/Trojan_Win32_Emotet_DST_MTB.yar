
rule Trojan_Win32_Emotet_DST_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DST!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {0f b6 07 0f b6 cb 03 c1 8b ce 99 f7 f9 8b 45 90 01 01 8a 8c 15 90 01 04 30 08 90 00 } //01 00 
		$a_81_1 = {79 57 74 47 4f 45 41 50 4a 66 69 51 35 6d 76 59 31 76 55 6f 72 34 37 75 73 36 35 59 } //00 00 
	condition:
		any of ($a_*)
 
}