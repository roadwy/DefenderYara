
rule Trojan_Win32_Copak_DJ_MTB{
	meta:
		description = "Trojan:Win32/Copak.DJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 1f 81 c7 04 00 00 00 29 f1 21 f2 39 c7 75 } //01 00 
		$a_01_1 = {5e 4f 81 c3 01 00 00 00 09 ff 47 81 fb 5e 46 00 01 75 } //00 00 
	condition:
		any of ($a_*)
 
}