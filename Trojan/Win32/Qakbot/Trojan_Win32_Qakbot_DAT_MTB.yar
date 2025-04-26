
rule Trojan_Win32_Qakbot_DAT_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DAT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 8b 4d f4 2b 4d f4 89 4d f4 8b 4d e8 8a 14 01 8b 75 e4 88 14 06 8a 55 f3 83 c0 01 88 55 f3 8b 7d ec 39 f8 89 45 e0 74 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}