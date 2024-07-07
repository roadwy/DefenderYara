
rule Trojan_Win32_Qakbot_SAK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.SAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 00 33 05 90 01 04 a3 90 0a 3c 00 a1 90 01 04 03 05 90 01 04 48 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 01 10 a1 90 01 04 03 05 90 01 04 a3 90 01 04 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}