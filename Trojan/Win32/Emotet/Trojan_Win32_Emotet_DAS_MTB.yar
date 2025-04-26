
rule Trojan_Win32_Emotet_DAS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 00 56 6a 00 6a 01 55 8b f8 53 ff d7 85 c0 90 13 8b 06 [0-03] 50 e8 ?? ?? ?? ?? 8b 4c 24 ?? 83 c4 04 6a 00 6a 00 56 50 6a 01 55 53 89 01 ff d7 5f 5e } //1
		$a_02_1 = {68 e0 07 00 00 03 ca 51 50 89 44 24 ?? ff d7 8b 44 24 ?? 83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 55 ff d3 8b ?? ?? ?? ?? ?? ?? ?? 51 8b f0 52 56 ff d7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}