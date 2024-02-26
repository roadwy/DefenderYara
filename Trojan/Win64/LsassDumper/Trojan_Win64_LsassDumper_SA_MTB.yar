
rule Trojan_Win64_LsassDumper_SA_MTB{
	meta:
		description = "Trojan:Win64/LsassDumper.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b c1 ff c1 40 30 2c 18 3b 4c 24 90 01 01 72 90 00 } //01 00 
		$a_03_1 = {44 30 00 48 8d 40 90 01 01 48 83 ea 90 01 01 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}