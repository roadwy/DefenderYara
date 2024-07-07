
rule Trojan_Win32_Qakbot_AF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c2 8b 55 d8 89 02 68 90 02 04 e8 90 02 04 8b 55 c4 03 55 a4 03 c2 89 45 a0 68 90 02 04 e8 90 02 04 8b d8 03 5d a0 68 90 02 04 e8 90 02 04 03 d8 8b 45 d8 33 18 89 5d a0 68 90 02 04 e8 90 02 04 03 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}