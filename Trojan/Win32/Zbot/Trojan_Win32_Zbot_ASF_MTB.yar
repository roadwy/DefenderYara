
rule Trojan_Win32_Zbot_ASF_MTB{
	meta:
		description = "Trojan:Win32/Zbot.ASF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 06 2b c2 03 c2 33 01 89 03 83 c1 04 47 8b c7 2b 45 90 01 01 75 90 00 } //1
		$a_01_1 = {83 c1 04 6a 40 68 00 30 00 00 51 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}