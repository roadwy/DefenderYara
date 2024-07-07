
rule Trojan_Win32_Trickbot_RC_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 4b 01 b8 90 01 04 f7 e9 c1 fa 90 01 01 89 d3 89 c8 c1 f8 90 01 01 29 c3 69 db 90 01 04 29 d9 89 cb 89 cf 03 7c 24 90 01 01 0f b6 0f 01 f1 b8 90 01 04 f7 e9 89 d6 c1 fe 90 01 01 89 c8 c1 f8 90 01 01 29 c6 69 f6 90 01 04 29 f1 89 ce 89 c8 03 44 24 90 01 01 89 44 24 90 01 01 89 44 24 90 01 01 89 3c 24 e8 90 01 04 0f b6 17 8b 44 24 90 01 01 0f b6 00 01 d0 8b 54 24 90 01 01 0f b6 04 02 89 ef 03 7c 24 90 01 01 8b 54 24 90 01 01 0f be 14 2a 89 54 24 90 01 01 89 04 24 e8 90 01 04 88 07 83 c5 90 01 01 3b 6c 24 90 01 01 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}