
rule Trojan_Win32_DllInject_MW_MTB{
	meta:
		description = "Trojan:Win32/DllInject.MW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 c9 88 4d bd 33 d2 88 55 bc 33 c0 88 45 bb 8a 4d bd 88 4d a4 8a 55 bc 88 55 a0 8a 45 bb 88 45 9c b9 90 01 04 c7 85 18 ff ff ff 90 01 04 89 8d 1c ff ff ff 8b 95 18 ff ff ff 8b 85 90 00 } //01 00 
		$a_00_1 = {0f 28 45 d0 0f 29 85 a0 fe ff ff 8b 4d 8c 0f 10 01 0f 29 85 b0 fe ff ff 0f 28 85 b0 fe ff ff 66 0f ef 85 a0 fe ff ff 0f 29 85 90 fe ff ff 0f 28 85 90 fe ff ff 8b 55 8c 0f 11 02 } //00 00 
	condition:
		any of ($a_*)
 
}