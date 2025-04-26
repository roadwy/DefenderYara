
rule Trojan_Win32_Qakbot_AZ_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b 8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 6a 00 e8 [0-04] 8b 55 d8 83 c2 04 03 55 a4 03 c2 40 89 45 ?? 8b 45 ?? 3b 45 ?? 0f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}