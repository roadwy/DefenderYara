
rule Trojan_Win32_Fareit_IT_MTB{
	meta:
		description = "Trojan:Win32/Fareit.IT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {31 c9 31 d2 90 02 30 80 34 01 90 01 01 ff 45 fc 41 89 d7 39 f9 90 01 02 05 90 01 04 ff e0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}