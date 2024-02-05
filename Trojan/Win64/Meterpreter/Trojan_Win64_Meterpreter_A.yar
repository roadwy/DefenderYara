
rule Trojan_Win64_Meterpreter_A{
	meta:
		description = "Trojan:Win64/Meterpreter.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec 74 90 01 01 81 90 01 01 aa fc 0d 7c 74 90 01 01 81 90 01 01 54 ca af 91 74 90 01 01 81 90 01 01 f2 32 f6 0e 90 00 } //01 00 
		$a_01_1 = {83 e8 05 c6 43 05 e9 89 43 06 ff 15 } //01 00 
		$a_01_2 = {c6 46 05 e9 2b c6 83 e8 05 89 46 06 } //00 00 
	condition:
		any of ($a_*)
 
}