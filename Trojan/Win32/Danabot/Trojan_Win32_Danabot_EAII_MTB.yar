
rule Trojan_Win32_Danabot_EAII_MTB{
	meta:
		description = "Trojan:Win32/Danabot.EAII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c6 03 d0 81 e2 ff 00 00 00 81 3d ?? ?? ?? ?? 8a 08 00 00 8b f2 89 35 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}