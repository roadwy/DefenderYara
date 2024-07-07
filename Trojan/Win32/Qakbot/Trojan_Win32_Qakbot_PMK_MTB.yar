
rule Trojan_Win32_Qakbot_PMK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}