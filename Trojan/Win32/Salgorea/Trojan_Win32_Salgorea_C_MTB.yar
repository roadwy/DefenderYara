
rule Trojan_Win32_Salgorea_C_MTB{
	meta:
		description = "Trojan:Win32/Salgorea.C!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 cc cf a0 8f dc c7 45 d0 53 69 47 38 } //01 00 
		$a_01_1 = {c7 45 c8 4f 91 31 af } //01 00 
		$a_01_2 = {c7 45 c4 f7 9e 05 81 } //00 00 
	condition:
		any of ($a_*)
 
}