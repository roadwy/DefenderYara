
rule Trojan_Win32_Copak_CL_MTB{
	meta:
		description = "Trojan:Win32/Copak.CL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {89 c9 46 31 03 43 4e 39 fb 75 e9 } //02 00 
		$a_03_1 = {31 31 47 41 bf 90 02 04 53 5b 39 c1 75 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}