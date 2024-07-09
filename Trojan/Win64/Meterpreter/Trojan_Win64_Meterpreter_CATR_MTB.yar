
rule Trojan_Win64_Meterpreter_CATR_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.CATR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c7 84 24 10 01 00 00 03 00 10 00 48 8d 94 24 e0 00 00 00 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? c7 44 24 20 40 00 00 00 41 b9 00 10 00 00 41 b8 00 10 00 00 33 d2 48 8b 4c 24 58 ff ?? ?? ?? ?? ?? 48 89 44 24 50 48 c7 44 24 20 00 00 00 00 41 b9 00 10 00 00 4c 8d 05 b8 1e 00 00 48 8b 54 24 50 48 8b 4c 24 58 ff ?? ?? ?? ?? ?? 48 8b 44 24 50 48 89 84 24 d8 01 00 00 48 8d 94 24 e0 00 00 00 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? 48 8b 4c 24 60 ff ?? ?? ?? ?? ?? 48 8b 4c 24 58 ff } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}