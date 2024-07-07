
rule Trojan_Win32_Nanobot_SPQ_MTB{
	meta:
		description = "Trojan:Win32/Nanobot.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb 26 00 00 00 2b d8 33 db 33 c3 2b d8 33 db 83 eb 1e 2b d8 33 c0 81 c3 97 00 00 00 03 c3 2b c0 05 97 00 00 00 83 c3 68 8b c3 58 5b 8b 45 fc 99 b9 5f 00 00 00 f7 f9 8b 45 fc 8b 4d e4 8a 14 11 88 94 05 d8 fd ff ff } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}