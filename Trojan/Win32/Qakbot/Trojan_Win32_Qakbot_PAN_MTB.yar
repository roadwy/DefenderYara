
rule Trojan_Win32_Qakbot_PAN_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {74 cf 81 f9 90 01 04 81 d7 23 19 00 00 81 d3 0c 05 00 00 bc ef 14 00 00 c8 f0 00 00 03 ec 25 90 01 04 f7 d6 85 df e6 2c 81 db 66 13 00 00 5e 90 00 } //1
		$a_03_1 = {51 51 3a ed 74 14 33 c0 40 eb 0b 8b 45 0c 89 45 f8 66 3b c0 74 f0 c9 c2 0c 00 68 90 01 04 e8 90 01 04 66 3b db 74 ce 55 8b ec 66 3b f6 74 cf 81 f9 fb 15 00 00 81 d7 23 19 00 00 81 d3 0c 90 00 } //1
		$a_00_2 = {f7 d0 0f 57 c0 66 0f 13 45 f8 eb ba 89 4d fc 8b 45 08 3a e4 74 26 55 8b ec 3a f6 74 00 51 51 66 3b ed 74 de 83 c0 01 8b 4d fc 66 3b d2 74 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=1
 
}