
rule Trojan_Win32_Emotet_DHS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DHS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {c1 e2 02 0f b6 85 90 01 04 c1 f8 04 0b d0 8b 8d 90 01 04 88 11 8b 95 90 1b 01 83 c2 01 89 95 90 1b 01 0f b6 85 90 1b 00 c1 e0 04 90 00 } //01 00 
		$a_00_1 = {6a 40 68 00 10 00 00 8d 55 0c 52 6a 00 8d 45 bc 50 ff 55 cc 50 ff 55 c8 8b 4d 0c 51 8b 55 08 52 8b 45 bc 50 ff 55 e8 83 c4 0c } //00 00 
	condition:
		any of ($a_*)
 
}