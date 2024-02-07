
rule PWS_Win32_QQpass_AU{
	meta:
		description = "PWS:Win32/QQpass.AU,SIGNATURE_TYPE_PEHSTR_EXT,11 00 10 00 04 00 00 05 00 "
		
	strings :
		$a_00_0 = {ff ff ff ff 06 00 00 00 71 71 2e 45 58 45 00 00 51 51 d3 c3 bb a7 b5 c7 c2 bc 00 } //0a 00 
		$a_00_1 = {46 3a 5c 6d 63 6b 5c 4b 6f 6c 2e 70 61 73 } //01 00  F:\mck\Kol.pas
		$a_00_2 = {51 51 3a 2d 28 } //01 00  QQ:-(
		$a_02_3 = {8b d8 83 7d ec 00 74 40 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 c0 8b 45 f4 e8 90 01 02 ff ff 50 e8 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}