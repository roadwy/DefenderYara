
rule Trojan_Win32_Emotet_VAA_MTB{
	meta:
		description = "Trojan:Win32/Emotet.VAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 f7 89 f8 89 55 b4 99 8b 7d b8 f7 ff 8b 7d f0 81 f7 ba 15 9b 7a 88 4d b3 8b 4d dc 8a 0c 11 88 4d ?? 8b 4d dc 89 55 ac 8b 55 b4 89 5d a8 8a 5d b2 88 1c 11 } //3
		$a_03_1 = {01 f1 21 f9 66 c7 45 ee 1a 6a 8b 75 e4 8b 7d ?? 8a 3c 3e 8b 55 dc 32 3c 0a 8b 4d e0 88 3c 39 8b 4d a8 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}