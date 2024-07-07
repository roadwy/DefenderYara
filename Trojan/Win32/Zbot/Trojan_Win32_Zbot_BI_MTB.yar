
rule Trojan_Win32_Zbot_BI_MTB{
	meta:
		description = "Trojan:Win32/Zbot.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 ce 2b c1 03 c7 81 1d 90 02 04 ef b4 45 00 33 c6 81 05 90 02 04 3e 78 00 00 89 45 90 01 01 8b 45 90 01 01 33 c6 2b c7 0f 85 90 00 } //1
		$a_03_1 = {33 c6 2b c7 89 01 8b 45 90 01 01 8b 4d 90 01 01 33 c6 2b c7 3b c8 0f 84 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}