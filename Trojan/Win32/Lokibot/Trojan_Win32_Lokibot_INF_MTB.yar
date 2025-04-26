
rule Trojan_Win32_Lokibot_INF_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.INF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 34 18 8a 16 80 f2 8b 88 16 40 3d 72 57 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}