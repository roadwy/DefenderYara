
rule Trojan_Win32_Fareit_POIV_MTB{
	meta:
		description = "Trojan:Win32/Fareit.POIV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {a8 16 40 00 1f 90 01 03 ce 2c 41 00 d5 2c 41 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}