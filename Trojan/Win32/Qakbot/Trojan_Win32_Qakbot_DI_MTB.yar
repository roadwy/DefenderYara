
rule Trojan_Win32_Qakbot_DI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 80 0d 00 00 03 05 90 01 04 a3 90 01 04 a1 90 01 04 03 05 90 01 04 8b 15 90 01 04 31 02 83 05 90 01 04 04 a1 90 01 04 83 c0 04 a3 90 01 04 a1 90 01 04 99 52 50 a1 90 01 04 33 d2 3b 54 24 04 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}