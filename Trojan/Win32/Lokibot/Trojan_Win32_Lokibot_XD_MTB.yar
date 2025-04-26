
rule Trojan_Win32_Lokibot_XD_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.XD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {bb 01 00 00 00 90 05 10 01 90 8b c2 03 c3 90 05 10 01 90 c6 00 ?? 90 05 10 01 90 43 81 fb ?? ?? ?? ?? 75 } //1
		$a_03_1 = {56 57 83 c4 [0-28] 8a 92 b8 eb 44 00 80 f2 e8 88 10 [0-08] c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}