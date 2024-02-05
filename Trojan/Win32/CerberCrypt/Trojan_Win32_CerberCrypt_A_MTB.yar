
rule Trojan_Win32_CerberCrypt_A_MTB{
	meta:
		description = "Trojan:Win32/CerberCrypt.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 06 32 c2 88 07 42 46 47 e9 } //01 00 
		$a_01_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}