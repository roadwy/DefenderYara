
rule Trojan_Win32_Qakbot_MR_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 f0 8b 55 08 8b 02 2b c6 8b 4d 08 89 01 8b 55 08 8b 02 83 c0 90 01 01 8b 4d 08 89 01 8b 55 08 8b 02 83 e8 90 01 01 8b 4d 08 89 01 5e 8b e5 5d c3 90 00 } //1
		$a_02_1 = {89 08 5b 5d c3 90 0a 2d 00 31 0d 90 01 04 c7 05 90 01 08 8b 1d 90 01 04 01 1d 90 01 04 a1 90 01 04 8b 0d 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}