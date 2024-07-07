
rule Trojan_Win32_Qakbot_EU_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 6a 66 e8 90 01 04 03 d8 6a 66 e8 90 01 04 2b d8 6a 66 e8 90 01 04 03 d8 89 5d 90 01 01 8b 45 90 01 01 8b 55 d8 01 02 8b 45 90 01 01 03 45 90 01 01 8b 55 90 01 01 31 02 83 45 ec 04 83 45 d8 04 8b 45 90 01 01 3b 45 90 01 01 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}