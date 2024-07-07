
rule PWS_Win32_Qakbot_MFP_MTB{
	meta:
		description = "PWS:Win32/Qakbot.MFP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 06 46 85 c0 74 90 01 01 57 29 3c e4 09 0c e4 52 c7 04 e4 90 01 04 59 bb 90 01 04 56 8f 45 f4 ff 75 f4 5a c7 45 fc 90 01 04 d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 90 01 01 57 33 3c e4 09 df 83 e0 00 09 f8 5f 81 e1 00 00 00 00 33 0c e4 83 ec 90 01 01 aa 49 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule PWS_Win32_Qakbot_MFP_MTB_2{
	meta:
		description = "PWS:Win32/Qakbot.MFP!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c7 45 c4 92 20 00 00 c7 45 c0 80 19 00 00 } //1
		$a_01_1 = {c7 45 e0 90 b9 03 00 c7 45 dc ad 08 00 00 c7 45 d8 7b 00 00 00 c7 45 d4 02 00 00 00 } //1
		$a_01_2 = {89 45 ec c7 45 b0 8a a5 08 00 8b 45 ec 3b 45 e4 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}