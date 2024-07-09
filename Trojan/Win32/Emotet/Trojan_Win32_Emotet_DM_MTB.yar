
rule Trojan_Win32_Emotet_DM_MTB{
	meta:
		description = "Trojan:Win32/Emotet.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 14 0a 03 c2 33 d2 bd ?? ?? ?? ?? f7 f5 8b 6c 24 40 03 d3 8a 04 2a 30 07 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}