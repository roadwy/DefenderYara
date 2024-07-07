
rule Trojan_Win64_Meterpreter_UNK_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.UNK!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 84 55 a4 00 00 00 8b 8d a0 00 00 00 66 33 c8 66 89 8c 55 a4 00 00 00 48 ff c2 48 83 fa 1b 72 de } //1
		$a_01_1 = {65 4c 8b 34 25 60 00 00 00 49 8b 5e 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}