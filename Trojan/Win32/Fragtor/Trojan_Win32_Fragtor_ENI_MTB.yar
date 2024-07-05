
rule Trojan_Win32_Fragtor_ENI_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.ENI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {60 e8 00 00 00 00 5d 81 ed 10 00 00 00 81 ed 0c db b5 00 } //00 00 
	condition:
		any of ($a_*)
 
}