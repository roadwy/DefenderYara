
rule Trojan_Win32_TrickBot_SA_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 5c 8c 10 8b 74 bc 10 89 74 8c 10 0f b6 f3 89 74 bc 10 8b 5c 8c 10 03 de 81 e3 ff 00 00 80 79 90 01 01 4b 81 cb 00 ff ff ff 43 0f b6 5c 9c 10 30 1c 2a 42 3b d0 72 90 00 } //1
		$a_01_1 = {75 39 2d 63 2a 4a 6e 54 2b 69 58 42 78 73 50 } //1 u9-c*JnT+iXBxsP
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}