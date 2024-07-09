
rule Trojan_Win32_Qakbot_DAA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 5c 24 23 80 f3 ?? 89 44 24 14 8b 44 24 28 01 f0 01 ca 88 5c 24 6f } //1
		$a_02_1 = {8b 45 dc 8b 4d e8 8a 14 01 8b 75 e4 88 14 06 83 c0 01 c7 45 f0 ?? ?? ?? ?? 8b 7d ec 39 f8 89 45 dc 74 cc eb db } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}