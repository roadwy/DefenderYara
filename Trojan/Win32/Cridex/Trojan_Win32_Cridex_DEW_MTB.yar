
rule Trojan_Win32_Cridex_DEW_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DEW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 05 00 00 01 00 "
		
	strings :
		$a_81_0 = {7a 46 6f 77 55 4e 73 57 78 4d } //01 00  zFowUNsWxM
		$a_81_1 = {4f 53 65 43 78 50 49 51 69 54 } //01 00  OSeCxPIQiT
		$a_81_2 = {4d 5a 57 59 6d 62 56 75 7a 42 } //01 00  MZWYmbVuzB
		$a_81_3 = {4d 42 53 46 47 49 47 43 58 4b 54 45 5a 52 46 42 4d 47 30 } //01 00  MBSFGIGCXKTEZRFBMG0
		$a_81_4 = {30 38 72 74 67 30 69 6d 75 77 72 68 39 79 33 75 6a 34 35 30 79 69 6a 33 74 } //00 00  08rtg0imuwrh9y3uj450yij3t
	condition:
		any of ($a_*)
 
}