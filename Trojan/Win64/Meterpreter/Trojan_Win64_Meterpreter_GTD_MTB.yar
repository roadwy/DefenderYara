
rule Trojan_Win64_Meterpreter_GTD_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.GTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 0f 1f 84 00 00 00 00 00 48 89 c2 83 e2 0f 0f b6 14 11 32 14 03 83 f2 a5 88 14 03 48 89 c2 48 8d 40 01 48 39 c6 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}