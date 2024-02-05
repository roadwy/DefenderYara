
rule Trojan_Win32_Azorult_NN_MTB{
	meta:
		description = "Trojan:Win32/Azorult.NN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {30 04 1e 83 ff 19 75 0e 6a 00 6a 00 6a 00 6a 00 ff 15 90 02 04 46 3b f7 90 18 e8 90 00 } //01 00 
		$a_02_1 = {30 04 33 83 90 01 02 90 18 46 3b f7 90 18 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}