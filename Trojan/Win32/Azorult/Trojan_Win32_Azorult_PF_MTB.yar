
rule Trojan_Win32_Azorult_PF_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {83 c2 01 89 95 90 01 04 81 bd 90 01 04 e2 02 00 00 73 36 8b 85 90 01 04 33 d2 b9 04 00 00 00 f7 f1 8b 85 90 01 04 0f be 0c 10 8b 95 90 01 04 0f b6 82 90 01 03 00 33 c1 8b 8d 90 01 04 88 81 90 01 03 00 eb af 90 09 06 00 8b 95 90 00 } //01 00 
		$a_02_1 = {83 c1 01 89 8d 90 01 04 83 bd 90 01 04 04 73 32 8b 85 90 01 04 33 d2 b9 04 00 00 00 f7 f1 8b 85 90 01 04 0f be 0c 10 8b 95 90 01 04 0f b6 44 15 90 01 01 33 c1 8b 8d 90 01 04 88 44 0d 90 01 01 eb b6 90 09 06 00 8b 8d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}