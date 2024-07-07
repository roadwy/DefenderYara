
rule Trojan_Win64_Meterpreter_DA_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 c9 41 0f b6 54 8a 08 30 53 ff } //1
		$a_01_1 = {41 0f b6 40 fd c1 e1 06 41 0b 0c 82 8b c1 c1 f8 10 41 88 04 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}