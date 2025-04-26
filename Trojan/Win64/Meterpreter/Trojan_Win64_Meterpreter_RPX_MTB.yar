
rule Trojan_Win64_Meterpreter_RPX_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {c6 44 24 50 50 c6 44 24 51 53 c6 44 24 52 51 c6 44 24 53 52 c6 44 24 54 56 c6 44 24 55 57 c6 44 24 56 55 c6 44 24 57 54 c6 44 24 58 41 c6 44 24 59 50 c6 44 24 5a 41 c6 44 24 5b 51 c6 44 24 5c 41 c6 44 24 5d 52 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}