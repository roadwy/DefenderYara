
rule Trojan_Win32_Trickbot_CK_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.CK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {33 d2 f7 f6 3b d3 74 90 01 01 0f b6 0c 17 0f b6 04 1f 88 0c 1f 90 02 10 88 04 17 90 00 } //01 00 
		$a_03_1 = {33 db 8a e0 c0 e8 02 2a 5c 24 90 01 01 c0 e4 06 2a dc 8a 64 24 90 01 01 f6 db 88 5c 24 90 01 01 8a f8 80 f7 30 22 f8 88 64 24 90 01 01 c0 e4 04 8a c7 8a dc 80 e7 3c 80 cc 03 f6 d0 f6 d3 0a d8 24 03 0a f8 f6 d3 8a 44 24 90 01 01 32 e7 0a dc 88 5c 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}