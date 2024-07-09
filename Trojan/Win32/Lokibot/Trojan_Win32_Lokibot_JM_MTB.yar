
rule Trojan_Win32_Lokibot_JM_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.JM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 12 80 f2 ?? 03 c3 73 ?? e8 ?? ?? ?? ff 88 10 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}