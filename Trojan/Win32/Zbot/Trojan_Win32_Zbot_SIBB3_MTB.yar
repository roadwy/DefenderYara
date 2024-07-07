
rule Trojan_Win32_Zbot_SIBB3_MTB{
	meta:
		description = "Trojan:Win32/Zbot.SIBB3!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {50 89 c7 be 90 02 10 8a 1d 90 02 0a 8a 3e 88 3f 47 46 46 50 8a 06 aa 00 5f 90 01 01 58 e2 90 02 0a 83 ec 90 01 01 6a 90 01 01 ff 35 90 01 04 ff 15 90 01 04 5a 29 c2 52 6a 90 01 01 6a 90 01 01 68 90 01 04 68 90 01 04 ff 15 90 01 04 5a 29 c2 90 00 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}