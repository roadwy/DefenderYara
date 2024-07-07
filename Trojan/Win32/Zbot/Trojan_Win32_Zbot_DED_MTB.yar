
rule Trojan_Win32_Zbot_DED_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 f6 2b c2 1b f1 a3 90 01 04 0f b6 0d 90 01 04 69 c9 ec e7 00 00 03 0d 90 01 04 89 0d 90 00 } //1
		$a_02_1 = {6b d2 61 03 ca 0f b6 05 90 01 04 2b c1 a2 90 01 04 8b 4d dc 83 e9 01 89 4d dc 8b 15 90 01 04 6b d2 61 33 c0 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}