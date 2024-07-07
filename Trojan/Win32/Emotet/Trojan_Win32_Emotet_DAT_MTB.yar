
rule Trojan_Win32_Emotet_DAT_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 30 68 90 01 04 68 90 01 04 6a 00 89 44 24 90 01 01 ff d6 8b f0 56 6a 00 ff 54 24 90 01 01 56 6a 00 89 44 24 90 01 01 ff 54 24 90 01 01 8b f0 8b 44 24 90 01 01 50 ff 54 24 90 00 } //1
		$a_02_1 = {68 e0 07 00 00 6a 00 57 ff d3 8b 54 24 90 01 01 68 e0 07 00 00 03 d6 8b f8 52 57 ff d5 90 02 0a 83 c4 0c 6a 00 50 68 00 30 00 00 56 6a 00 51 ff d3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}