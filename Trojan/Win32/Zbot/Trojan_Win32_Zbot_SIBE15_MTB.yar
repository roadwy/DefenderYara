
rule Trojan_Win32_Zbot_SIBE15_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBE15!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {64 8b 15 30 00 00 00 8b 52 0c 8b 52 14 8b 72 28 b9 90 01 04 33 ff 33 c0 ac 3c 90 01 01 7c 90 01 01 2c 90 01 01 c1 cf 90 01 01 03 f8 e2 90 01 01 81 ff 90 01 04 8b 42 10 8b 12 75 90 00 } //1
		$a_00_1 = {8b f2 2b c8 8a 14 01 30 10 40 4e 75 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}