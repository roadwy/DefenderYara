
rule Trojan_Win32_Emotet_DS_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 33 33 d2 69 c8 ?? ?? 00 00 0f b6 06 c7 45 fc ?? 00 00 00 49 0f af c8 8b c3 f7 75 fc 8a 44 15 ?? 30 84 19 ?? ?? ?? ?? 43 81 fb ?? ?? 00 00 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}