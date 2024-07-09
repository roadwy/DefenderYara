
rule PWS_Win32_Zbot_IQ{
	meta:
		description = "PWS:Win32/Zbot.IQ,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 8b 1f 66 83 c3 ?? 66 89 1f 66 83 07 ?? 6a ?? 58 39 d0 47 83 c7 01 81 c3 ?? ?? 40 00 74 08 4e 42 f7 c0 ?? ?? 40 00 50 c7 04 24 ?? ?? 40 00 5a 39 fa 75 a3 81 f6 ?? ?? 40 00 74 08 01 d8 81 ee ?? ?? 40 00 41 68 ?? ?? ?? 00 8b 14 24 58 3b d1 0f 85 58 ff ff ff 89 d2 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}