
rule Trojan_Win32_Lokibot_YTR_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.YTR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 06 89 45 f8 ?? 8b 45 f8 05 ?? ?? ?? ?? 8a 00 34 27 8b d3 03 55 f8 88 02 ?? ?? ff 06 81 3e } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}