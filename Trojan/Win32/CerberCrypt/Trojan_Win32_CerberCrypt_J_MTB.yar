
rule Trojan_Win32_CerberCrypt_J_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 06 90 32 c2 88 07 } //02 00 
		$a_01_1 = {6a 40 90 68 00 10 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}