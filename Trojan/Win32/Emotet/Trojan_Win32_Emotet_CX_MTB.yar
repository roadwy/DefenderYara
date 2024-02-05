
rule Trojan_Win32_Emotet_CX_MTB{
	meta:
		description = "Trojan:Win32/Emotet.CX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 0f b6 0c 10 8b 55 f8 0f b6 84 15 d8 d5 ff ff 33 c1 8b 4d f8 88 84 0d d8 d5 ff ff 50 53 8b c3 2b db 33 c0 2b d8 b8 84 00 00 00 81 f3 ee 00 00 00 2b c3 83 f3 1c 2b d8 83 e8 43 } //00 00 
	condition:
		any of ($a_*)
 
}