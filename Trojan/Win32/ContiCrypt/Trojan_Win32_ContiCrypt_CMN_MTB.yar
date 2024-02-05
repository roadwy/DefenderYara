
rule Trojan_Win32_ContiCrypt_CMN_MTB{
	meta:
		description = "Trojan:Win32/ContiCrypt.CMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 c1 0b f7 e9 03 d1 c1 fa 04 8b c2 c1 e8 1f 03 c2 } //01 00 
		$a_01_1 = {83 c1 0b f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 c2 } //00 00 
	condition:
		any of ($a_*)
 
}