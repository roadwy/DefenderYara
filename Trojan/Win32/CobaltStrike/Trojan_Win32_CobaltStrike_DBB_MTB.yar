
rule Trojan_Win32_CobaltStrike_DBB_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.DBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {35 53 2a 00 00 81 c6 19 d3 ff ff 3b c8 0f 8d ce 01 00 00 8d 81 f9 04 00 00 3b f0 0f 8f c0 01 00 00 8b c3 35 e7 2c 00 00 57 3b d0 0f 84 fb 00 00 00 8b 7c 24 38 8d 42 ed 57 50 8b 44 24 24 35 43 03 00 00 50 8d 81 e5 fe ff ff 50 } //4
		$a_01_1 = {59 6e 63 67 41 34 30 64 33 33 } //1 YncgA40d33
		$a_01_2 = {47 49 62 4f 54 4e 36 35 } //1 GIbOTN65
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=6
 
}