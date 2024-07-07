
rule Trojan_Win32_Zbot_YTL_MTB{
	meta:
		description = "Trojan:Win32/Zbot.YTL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {31 fb 8b 7c 24 08 03 7c 24 08 2b 7c 24 08 31 fb 33 5c 24 90 01 01 89 5c 24 90 00 } //1
		$a_02_1 = {68 01 00 00 00 8d 44 24 90 01 01 50 8b 5c 24 90 01 01 03 5c 24 90 00 } //1
		$a_80_2 = {4b 73 64 6e 59 59 65 32 } //KsdnYYe2  1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}