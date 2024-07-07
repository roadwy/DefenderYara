
rule Trojan_Win32_Trickbot_M_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {6a 17 68 05 e8 00 00 52 e8 } //1
		$a_02_1 = {6a 40 68 00 10 00 00 90 01 01 6a 00 ff d3 90 00 } //1
		$a_00_2 = {8a d9 2a da 32 19 32 d8 88 19 03 cf 3b 4d } //1
		$a_80_3 = {48 65 79 2c 20 49 20 6d 69 73 73 3f } //Hey, I miss?  1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}