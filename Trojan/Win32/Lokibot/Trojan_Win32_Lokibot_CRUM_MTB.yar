
rule Trojan_Win32_Lokibot_CRUM_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.CRUM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 2c 24 04 01 04 24 8b 04 24 31 01 } //1
		$a_03_1 = {8b 54 24 14 8b 44 24 10 33 d7 33 c2 2b d8 81 3d 90 02 09 89 44 24 10 75 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}