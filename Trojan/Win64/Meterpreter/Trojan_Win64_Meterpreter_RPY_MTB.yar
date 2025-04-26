
rule Trojan_Win64_Meterpreter_RPY_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 8a 04 3e 41 32 84 1d e8 03 00 00 48 ff c3 42 88 04 3f 49 ff c7 83 e3 0f 49 39 ef 0f 8d 1b ff ff ff 48 85 db 0f 84 68 ff ff ff 49 39 f7 7c d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}