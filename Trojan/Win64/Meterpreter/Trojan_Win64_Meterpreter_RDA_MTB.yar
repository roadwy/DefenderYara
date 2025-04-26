
rule Trojan_Win64_Meterpreter_RDA_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 ec 33 45 f4 89 45 e8 8b 45 e8 c1 e8 18 88 45 bc 8b 45 e8 c1 e8 10 88 45 bd 8b 45 e8 c1 e8 08 88 45 be 8b 45 e8 88 45 bf b8 31 00 00 00 48 89 c1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}