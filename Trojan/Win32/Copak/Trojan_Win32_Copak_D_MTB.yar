
rule Trojan_Win32_Copak_D_MTB{
	meta:
		description = "Trojan:Win32/Copak.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 37 47 89 ca 39 c7 90 09 0c 00 be 90 01 04 09 d1 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}