
rule Trojan_Win32_Qakbot_DB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d e8 2b c8 8b 15 ?? ?? ?? ?? 2b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 05 7c 13 0e 01 a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d f8 8b 15 ?? ?? ?? ?? 89 91 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Qakbot_DB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 03 d8 a1 [0-04] 89 18 a1 [0-04] 03 05 [0-04] a3 [0-04] 6a 00 e8 [0-04] 03 05 [0-04] 40 8b 15 [0-04] 33 02 a3 [0-04] a1 [0-04] 8b 15 [0-04] 89 10 8b 45 f8 83 c0 04 89 45 f8 33 c0 a3 [0-04] a1 [0-04] 83 c0 04 03 05 [0-04] a3 [0-04] 8b 45 f8 3b 05 [0-04] 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}