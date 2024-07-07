
rule Trojan_Win32_TrickBot_HB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.HB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c2 99 f7 bd 90 01 04 8b 45 10 03 85 90 01 04 8a 08 32 8c 15 90 01 04 8b 55 10 03 95 90 01 04 88 0a 8b 85 90 01 04 83 c0 01 89 85 90 01 04 e9 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_TrickBot_HB_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.HB!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 7d 10 2b f9 53 50 8b 01 33 02 52 8b d0 51 03 cf 51 58 89 10 59 5a 42 42 58 42 42 3b 55 08 72 02 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}