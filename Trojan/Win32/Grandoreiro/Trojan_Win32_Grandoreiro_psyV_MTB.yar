
rule Trojan_Win32_Grandoreiro_psyV_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 07 00 "
		
	strings :
		$a_01_0 = {56 b9 00 00 00 00 ff 55 08 50 56 ff 95 88 00 00 00 83 c4 18 33 c0 50 68 80 00 00 00 6a 03 50 6a 01 68 00 00 00 80 57 ff 55 5c 83 f8 ff 74 e5 } //00 00 
	condition:
		any of ($a_*)
 
}