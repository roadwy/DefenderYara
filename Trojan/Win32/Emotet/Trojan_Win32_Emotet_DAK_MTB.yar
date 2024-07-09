
rule Trojan_Win32_Emotet_DAK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 44 24 18 02 c3 0f b6 c8 8a 54 0c 1c 8b 44 24 10 8b 8c 24 ?? ?? ?? ?? 30 14 08 8b 8c 24 ?? ?? ?? ?? 40 3b c1 89 44 24 10 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}