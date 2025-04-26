
rule Trojan_Win32_Emotet_U_MTB{
	meta:
		description = "Trojan:Win32/Emotet.U!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {6a 00 6a 40 68 00 30 00 00 56 6a 00 8b d8 ff 15 ?? ?? ?? ?? 50 ff 15 ?? ?? ?? ?? 56 8b f8 53 57 e8 } //1
		$a_02_1 = {8b 44 24 24 8b 08 8b 54 24 20 51 50 8b 44 24 18 52 53 6a 01 53 50 ff 15 ?? ?? ?? 00 5f 85 c0 5b 0f 95 c0 5e 83 c4 08 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}