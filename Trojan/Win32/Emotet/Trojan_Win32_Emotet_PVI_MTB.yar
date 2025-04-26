
rule Trojan_Win32_Emotet_PVI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 03 c1 99 b9 98 04 00 00 f7 f9 8b 85 ?? ?? ff ff 8d 76 01 8a 8c 15 ?? ?? ff ff 30 4e ff } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}