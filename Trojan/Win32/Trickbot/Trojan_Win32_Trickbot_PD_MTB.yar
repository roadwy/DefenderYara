
rule Trojan_Win32_Trickbot_PD_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8b 45 f4 33 d2 b9 0a 00 00 00 f7 f1 8b 45 f0 0f b6 0c 10 8b 55 f4 0f b6 82 90 01 04 33 c1 8b 4d f4 88 81 90 00 } //10
		$a_02_1 = {52 6a 40 68 04 2e 00 00 68 90 01 04 ff 15 90 01 04 8b 45 ec 50 6a 01 b9 90 01 04 ff d1 90 00 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*1) >=11
 
}