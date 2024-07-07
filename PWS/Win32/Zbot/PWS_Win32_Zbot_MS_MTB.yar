
rule PWS_Win32_Zbot_MS_MTB{
	meta:
		description = "PWS:Win32/Zbot.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {50 8b d8 e8 90 01 04 85 c0 74 90 01 01 49 75 90 01 01 58 90 00 } //1
		$a_02_1 = {51 8b 0f e8 90 01 04 47 4b 8b c3 59 c3 90 00 } //1
		$a_02_2 = {8b 06 32 c1 e8 90 01 04 c3 90 00 } //1
		$a_00_3 = {88 07 46 c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}