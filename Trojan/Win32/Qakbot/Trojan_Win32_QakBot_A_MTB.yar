
rule Trojan_Win32_QakBot_A_MTB{
	meta:
		description = "Trojan:Win32/QakBot.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 dc 8b 45 dc 83 e8 04 89 45 dc 33 c0 89 45 b4 33 c0 89 45 b0 c7 45 c4 02 00 00 00 c7 45 bc 01 00 00 00 8b 45 e4 8b 10 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}