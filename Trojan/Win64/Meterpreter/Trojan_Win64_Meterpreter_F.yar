
rule Trojan_Win64_Meterpreter_F{
	meta:
		description = "Trojan:Win64/Meterpreter.F,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 c9 48 81 e9 ?? ?? ?? ?? 48 8d 05 ?? ?? ?? ?? 48 bb ?? ?? ?? ?? ?? ?? ?? ?? 48 31 58 27 48 2d f8 ff ff ff e2 f4 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}