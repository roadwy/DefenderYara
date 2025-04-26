
rule Trojan_Win32_Emotet_DAR_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 10 83 c4 04 6a 00 6a 00 89 01 ff 15 ?? ?? ?? ?? 8b 54 24 0c 8b 02 6a 00 6a 00 56 50 6a 01 55 53 ff d7 85 c0 } //1
		$a_02_1 = {8b 44 24 1c 83 c4 0c 6a 00 6a 40 68 00 30 00 00 50 6a 00 56 ff d5 8b 4c 24 10 51 8b f0 53 56 ff ?? ?? ?? 8b } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}