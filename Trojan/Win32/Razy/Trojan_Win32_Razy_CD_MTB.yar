
rule Trojan_Win32_Razy_CD_MTB{
	meta:
		description = "Trojan:Win32/Razy.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {74 01 ea 31 0a 01 d8 81 c2 04 00 00 00 46 39 fa 75 ec } //02 00 
		$a_03_1 = {74 01 ea 31 01 81 c1 04 00 00 00 81 c7 90 02 04 bb 90 02 04 39 f1 75 e4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}