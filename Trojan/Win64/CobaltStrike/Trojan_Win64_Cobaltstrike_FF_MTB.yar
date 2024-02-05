
rule Trojan_Win64_Cobaltstrike_FF_MTB{
	meta:
		description = "Trojan:Win64/Cobaltstrike.FF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {0f be 00 48 63 4c 24 34 0f b6 8c 0c 80 00 00 00 33 c1 88 44 24 2c 0f b6 54 24 2c 48 8d 4c 24 60 } //01 00 
		$a_01_1 = {40 32 2c 11 41 8d 53 ff 40 88 2c 11 44 32 34 01 44 89 d8 44 88 34 01 } //00 00 
	condition:
		any of ($a_*)
 
}