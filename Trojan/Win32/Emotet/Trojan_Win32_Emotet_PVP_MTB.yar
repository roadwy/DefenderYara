
rule Trojan_Win32_Emotet_PVP_MTB{
	meta:
		description = "Trojan:Win32/Emotet.PVP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 54 24 1b 03 c2 99 b9 73 08 00 00 f7 f9 8b 84 24 90 01 04 83 c0 01 89 84 24 90 01 04 8a 94 14 90 01 04 30 54 03 ff 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}