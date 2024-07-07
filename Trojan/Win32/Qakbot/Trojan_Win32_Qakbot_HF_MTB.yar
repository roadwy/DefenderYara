
rule Trojan_Win32_Qakbot_HF_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.HF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c0 04 a3 90 09 3f 00 01 10 a1 90 01 04 03 05 90 01 04 a3 90 01 04 6a 00 e8 90 01 04 03 05 90 01 04 40 8b 15 90 01 04 33 02 a3 90 01 04 a1 90 01 04 8b 15 90 01 04 89 10 a1 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}