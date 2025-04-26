
rule Trojan_Win32_Emotet_ID_MTB{
	meta:
		description = "Trojan:Win32/Emotet.ID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {5e 5b 5d c3 8b 44 24 ?? 8b 4c 24 ?? 81 f1 ?? ?? ?? ?? 8b 54 24 ?? 8a 1c 02 8b 74 24 ?? 88 1c 06 01 c8 8b 4c 24 ?? 39 c8 89 44 24 ?? 74 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}