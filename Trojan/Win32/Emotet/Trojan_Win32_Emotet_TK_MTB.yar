
rule Trojan_Win32_Emotet_TK_MTB{
	meta:
		description = "Trojan:Win32/Emotet.TK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 8b cb 99 f7 f9 8b 45 ?? 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? ?? ?? ?? ?? ?? ?? 8b 45 ?? 5e 5b ?? ?? 33 c0 8b 4d ?? 5f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}