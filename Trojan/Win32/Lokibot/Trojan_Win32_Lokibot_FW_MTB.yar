
rule Trojan_Win32_Lokibot_FW_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.FW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4c 24 04 ba ?? ?? ?? ?? 56 2b d1 be ?? ?? 00 00 8a 04 0a 34 ?? 88 01 41 4e 75 f5 b8 ?? ?? 00 00 5e c3 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}