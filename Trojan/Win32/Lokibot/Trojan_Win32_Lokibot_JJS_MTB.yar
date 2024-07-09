
rule Trojan_Win32_Lokibot_JJS_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.JJS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 db b0 6e 8b d3 ?? 90 1b 00 03 d6 89 14 24 8a 97 ?? ?? ?? ?? 90 90 32 d0 8b 04 24 88 10 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}