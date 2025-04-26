
rule Trojan_Win32_Qakbot_MRU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MRU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 08 2b cf 33 d2 8b c7 f7 75 10 8a 04 1a 8b 55 fc 32 04 17 88 04 39 47 83 ee 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}