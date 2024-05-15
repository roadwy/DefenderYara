
rule Trojan_Win32_CerberCrypt_D_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b f8 90 8b df } //02 00 
		$a_01_1 = {8a 06 90 32 c2 } //02 00 
		$a_01_2 = {6a 40 68 00 30 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}