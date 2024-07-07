
rule Trojan_Win32_Qbot_AC_MTB{
	meta:
		description = "Trojan:Win32/Qbot.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b d1 c7 45 e8 90 01 04 c7 45 ec 90 01 04 8a 44 15 90 01 01 34 90 01 01 88 44 15 90 01 01 42 83 fa 0c 7c 90 01 01 88 4d 90 01 01 8d 55 90 01 01 eb 90 00 } //1
		$a_03_1 = {8b d1 c7 45 f8 90 01 04 c6 45 fc 90 01 01 8a 44 15 90 01 01 2c 2d 88 44 15 90 01 01 42 83 fa 09 7c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}