
rule Trojan_Win32_Qakbot_HC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d8 03 1d 90 01 04 43 90 02 07 03 d8 43 a1 90 01 04 33 18 89 1d 90 02 0b 8b 1d 90 01 04 2b d8 90 02 07 2b d8 90 02 07 2b d8 a1 90 01 04 89 18 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}