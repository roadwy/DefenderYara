
rule Trojan_Win32_Zusy_SPL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SPL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {4d 6f 72 61 6c 65 41 62 75 6e 64 61 6e 74 } //01 00  MoraleAbundant
		$a_81_1 = {54 6f 72 74 75 72 65 53 68 61 72 65 } //01 00  TortureShare
		$a_81_2 = {54 75 6d 6f 75 72 43 72 6f 70 } //00 00  TumourCrop
	condition:
		any of ($a_*)
 
}