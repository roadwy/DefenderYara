
rule Trojan_Win32_Emotet_LI_MTB{
	meta:
		description = "Trojan:Win32/Emotet.LI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 8c 24 90 01 04 8a 04 31 8a 94 14 90 01 04 32 c2 88 04 31 8b 84 24 90 01 04 41 89 8c 24 90 01 04 8b c8 48 85 c9 89 84 24 90 01 04 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}