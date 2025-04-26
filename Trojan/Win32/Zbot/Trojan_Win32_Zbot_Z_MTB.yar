
rule Trojan_Win32_Zbot_Z_MTB{
	meta:
		description = "Trojan:Win32/Zbot.Z!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 ff 00 74 ?? 83 ef 04 83 c6 04 8b 4e fc 89 8b ?? ?? ?? ?? 83 c3 04 81 ab } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}