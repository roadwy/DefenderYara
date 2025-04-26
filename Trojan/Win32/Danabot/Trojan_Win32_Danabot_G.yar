
rule Trojan_Win32_Danabot_G{
	meta:
		description = "Trojan:Win32/Danabot.G,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 fe 00 74 36 29 c0 48 23 02 83 ea fc f7 d8 83 e8 26 8d 40 fe 83 c0 01 29 f8 6a ff 5f 21 c7 c7 41 00 00 00 00 00 31 01 83 c1 04 83 ee 04 8d 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}