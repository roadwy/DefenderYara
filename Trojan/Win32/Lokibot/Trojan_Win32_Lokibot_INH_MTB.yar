
rule Trojan_Win32_Lokibot_INH_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.INH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 90 90 8b 55 f8 03 d3 8a 12 90 90 80 f2 20 8b 4d f8 03 cb 88 11 90 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}