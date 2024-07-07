
rule Trojan_Win32_Lokibot_DB_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b c6 03 c3 a3 90 01 04 a1 90 01 04 8a 80 90 01 04 34 b1 a2 90 01 04 a1 90 01 04 8a 15 90 01 04 88 10 83 05 e4 1b 47 00 02 90 90 43 81 fb 4d 5e 00 00 75 90 00 } //1
		$a_03_1 = {bb ba 8a 02 00 6a 00 e8 90 01 04 90 90 4b 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}