
rule Trojan_Win32_Glupteba_MU_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {55 8b ec 51 56 8b 45 0c 89 45 fc 8b 0d 90 01 04 89 4d 08 68 90 01 04 ff 15 90 01 04 8b f0 03 75 fc 68 90 01 04 ff 15 90 01 04 03 f0 8b 55 08 03 32 8b 45 08 89 30 5e 8b e5 5d c3 90 00 } //01 00 
		$a_02_1 = {89 02 5f 5d c3 90 0a 32 00 31 0d 90 01 04 c7 05 90 02 08 a1 90 01 04 01 05 90 02 06 8b 15 90 01 04 a1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}