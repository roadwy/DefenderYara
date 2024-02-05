
rule Backdoor_Win64_Meterpreter_AG_MTB{
	meta:
		description = "Backdoor:Win64/Meterpreter.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {c5 cb f3 ff 0f af 90 01 01 41 8b d0 c1 ea 10 90 00 } //01 00 
		$a_03_1 = {97 04 00 88 14 01 41 8b d0 ff 90 02 06 48 63 0d 90 01 04 48 8b 05 90 01 04 c1 ea 08 88 14 01 ff 05 90 00 } //01 00 
		$a_03_2 = {05 ad c0 e1 ff 03 c8 31 90 01 05 49 81 f9 90 01 04 0f 8c 90 01 02 ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}