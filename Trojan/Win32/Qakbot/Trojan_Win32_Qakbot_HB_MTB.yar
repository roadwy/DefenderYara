
rule Trojan_Win32_Qakbot_HB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 10 8b 45 c4 03 45 a4 89 45 a0 90 02 07 8b 5d a0 2b d8 90 02 07 2b d8 8b 45 d8 33 18 89 5d a0 90 02 07 8b 5d a0 2b d8 90 02 07 2b d8 90 02 07 2b d8 8b 45 d8 89 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}