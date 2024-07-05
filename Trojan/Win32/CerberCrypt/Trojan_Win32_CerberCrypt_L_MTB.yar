
rule Trojan_Win32_CerberCrypt_L_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.L!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 } //02 00 
		$a_01_1 = {8a 06 90 32 c2 90 88 07 } //00 00 
	condition:
		any of ($a_*)
 
}