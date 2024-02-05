
rule Trojan_Win32_Fareit_DRLP_MTB{
	meta:
		description = "Trojan:Win32/Fareit.DRLP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 00 02 2f 33 ca 52 e5 ed 8b 4e bc ef 3c e0 21 26 } //00 00 
	condition:
		any of ($a_*)
 
}