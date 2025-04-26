
rule Trojan_Win32_Zbot_SIBV_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 db 39 5d ?? 76 ?? 8d 64 24 00 8a 0c 33 33 c0 88 4d ?? 8a 14 38 8b 4d ?? d2 e2 8a 4d 90 1b 02 32 d0 02 d3 32 ca 40 88 4d 90 1b 02 88 0c 33 83 f8 ?? 72 ?? 33 d2 8b c3 b9 ?? ?? ?? ?? f7 f1 43 8a 14 3a 32 55 90 1b 02 88 54 33 ?? 3b 5d 90 1b 00 72 ?? ff 4d 90 1b 03 79 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}