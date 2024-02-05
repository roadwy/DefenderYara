
rule Trojan_Win32_Injuke_CD_MTB{
	meta:
		description = "Trojan:Win32/Injuke.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {f7 d1 81 e9 90 02 04 81 c1 90 02 04 c1 e1 08 41 81 c1 90 02 04 31 cb 59 01 d8 90 00 } //01 00 
		$a_01_1 = {33 04 24 31 04 24 33 04 24 } //00 00 
	condition:
		any of ($a_*)
 
}