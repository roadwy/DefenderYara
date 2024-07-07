
rule Trojan_Win64_Meterpreter_MKA_MTB{
	meta:
		description = "Trojan:Win64/Meterpreter.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b d0 49 2b c8 49 63 c1 4c 8d 1d 90 01 04 42 8a 04 18 32 04 11 88 02 41 8d 41 01 25 90 01 04 7d 07 ff c8 83 c8 f0 ff c0 48 ff c2 44 8b c8 49 ff ca 75 d0 49 8b c0 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}