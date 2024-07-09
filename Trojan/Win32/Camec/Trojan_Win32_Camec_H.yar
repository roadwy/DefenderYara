
rule Trojan_Win32_Camec_H{
	meta:
		description = "Trojan:Win32/Camec.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 3b f3 0f 8c ?? 00 00 00 66 6b ff 40 66 8b 45 dc 0f 80 ?? 01 00 00 66 03 fe 0f 80 ?? 01 00 00 66 05 06 00 0f 80 ?? 01 00 00 66 3d 08 00 } //1
		$a_03_1 = {51 ff d6 6a ?? 8d ?? ?? ?? ff ff ?? ff d6 6a ?? 8d ?? ?? ?? ff ff ?? ff d6 6a ?? 8d ?? ?? ?? ff ff ?? ff d6 6a } //1
		$a_00_2 = {46 49 4f 62 6a 65 63 74 57 69 74 68 53 69 74 65 5f 53 65 74 53 69 74 65 } //1 FIObjectWithSite_SetSite
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}