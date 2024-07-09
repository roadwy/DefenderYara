
rule Trojan_Win32_Slupim_A{
	meta:
		description = "Trojan:Win32/Slupim.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3b c3 74 0d 8b c8 e8 ?? ?? ff ff 89 44 24 (14|18) eb 04 89 5c 24 (14|18) 6a 0c ?? 0f 00 00 00 68 ?? ?? ?? 00 8d 8c 24 ?? 00 00 00 89 ?? 24 ?? 00 00 00 89 9c 24 ?? 00 00 00 88 9c 24 ?? 00 00 00 e8 ?? ?? fe ff } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}