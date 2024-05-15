
rule Trojan_Win32_Midie_NB_MTB{
	meta:
		description = "Trojan:Win32/Midie.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 0a 00 "
		
	strings :
		$a_01_0 = {c1 e0 03 c1 eb 02 90 } //02 00 
		$a_81_1 = {5f 63 72 79 70 74 65 64 2e 64 6c 6c } //02 00  _crypted.dll
		$a_81_2 = {4d 53 49 47 61 6d 65 } //00 00  MSIGame
	condition:
		any of ($a_*)
 
}