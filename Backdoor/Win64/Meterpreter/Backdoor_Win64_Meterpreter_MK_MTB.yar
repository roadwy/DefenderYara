
rule Backdoor_Win64_Meterpreter_MK_MTB{
	meta:
		description = "Backdoor:Win64/Meterpreter.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 ff c0 89 44 24 20 8b 84 24 90 02 04 39 44 24 20 7d 50 48 8b 4c 24 78 e8 90 02 04 48 63 4c 24 20 48 8b 94 24 90 02 04 48 63 0c 8a 48 89 4c 24 58 48 8b 40 10 48 89 44 24 50 48 8d 4c 24 28 e8 90 02 04 48 63 4c 24 20 48 8b 40 10 48 8b 54 24 50 4c 8b 44 24 58 42 0f b6 14 02 88 14 08 eb 99 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}