
rule Trojan_Win64_Meterpreter_CCIQ_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.CCIQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {c7 44 24 20 40 00 00 00 41 b9 00 30 00 00 41 b8 ?? ?? 00 00 ba 00 00 00 00 48 89 c1 48 8b 05 ?? 6e 01 00 ff d0 } //1
		$a_03_1 = {48 c7 44 24 20 00 00 00 00 41 b9 ?? ?? 00 00 4c 8d 05 ?? ?? ?? ?? 48 89 c1 48 8b 05 ?? 6e 01 00 ff d0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}