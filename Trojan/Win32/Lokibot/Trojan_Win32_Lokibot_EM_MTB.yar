
rule Trojan_Win32_Lokibot_EM_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.EM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 1e 90 8b 06 83 c0 01 73 05 e8 c2 a6 f8 ff 51 b9 38 00 00 00 33 d2 f7 f1 59 81 fa ff 00 00 00 76 05 e8 a2 a6 f8 ff 8b c1 03 06 73 05 e8 9f a6 f8 ff 88 10 90 43 81 fb 20 60 4e 1e 75 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}