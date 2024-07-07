
rule Trojan_Win32_Qbot_PBG_MTB{
	meta:
		description = "Trojan:Win32/Qbot.PBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_03_0 = {fc 8b 4d 0c 90 13 ac 02 c3 90 13 32 c3 8b f6 90 13 8b ff c0 c8 e6 90 13 8b db aa 90 13 8b e4 49 e9 90 00 } //10
		$a_01_1 = {6d 75 73 74 } //1 must
		$a_03_2 = {8b 74 64 04 f3 a4 be 90 01 04 68 00 00 00 00 ff d3 4e 0f 85 90 01 04 c2 04 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_03_2  & 1)*10) >=21
 
}