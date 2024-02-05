
rule Trojan_Win32_Fareit_SRP_MTB{
	meta:
		description = "Trojan:Win32/Fareit.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {8a 04 3b 2c 0c 34 7e 2c 5a 88 04 3b 47 3b 7d f0 72 } //00 00 
	condition:
		any of ($a_*)
 
}