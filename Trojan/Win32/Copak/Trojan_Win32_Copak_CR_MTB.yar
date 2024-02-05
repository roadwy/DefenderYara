
rule Trojan_Win32_Copak_CR_MTB{
	meta:
		description = "Trojan:Win32/Copak.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {31 18 40 39 f8 75 e9 } //02 00 
		$a_01_1 = {31 33 81 c3 04 00 00 00 40 09 f8 39 cb 75 ec } //02 00 
		$a_01_2 = {31 06 42 29 ca 46 01 d2 39 fe 75 df } //00 00 
	condition:
		any of ($a_*)
 
}