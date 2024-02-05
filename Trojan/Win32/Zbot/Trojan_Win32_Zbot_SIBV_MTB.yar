
rule Trojan_Win32_Zbot_SIBV_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 db 39 5d 90 01 01 76 90 01 01 8d 64 24 00 8a 0c 33 33 c0 88 4d 90 01 01 8a 14 38 8b 4d 90 01 01 d2 e2 8a 4d 90 1b 02 32 d0 02 d3 32 ca 40 88 4d 90 1b 02 88 0c 33 83 f8 90 01 01 72 90 01 01 33 d2 8b c3 b9 90 01 04 f7 f1 43 8a 14 3a 32 55 90 1b 02 88 54 33 90 01 01 3b 5d 90 1b 00 72 90 01 01 ff 4d 90 1b 03 79 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}