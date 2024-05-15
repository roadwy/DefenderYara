
rule Trojan_Win32_CerberCrypt_I_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 46 47 49 90 83 f9 } //00 00 
	condition:
		any of ($a_*)
 
}