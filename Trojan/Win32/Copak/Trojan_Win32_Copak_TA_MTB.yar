
rule Trojan_Win32_Copak_TA_MTB{
	meta:
		description = "Trojan:Win32/Copak.TA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {31 1f 81 e9 90 01 04 ba 90 01 04 81 c7 04 00 00 00 40 39 f7 75 e3 90 00 } //01 00 
		$a_01_1 = {39 c0 74 01 } //00 00 
	condition:
		any of ($a_*)
 
}