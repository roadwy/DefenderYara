
rule Trojan_BAT_Remcos_MK_MTB{
	meta:
		description = "Trojan:BAT/Remcos.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {57 1d a2 1f 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 c3 00 00 00 14 00 00 00 f3 00 00 00 89 } //01 00 
		$a_01_1 = {24 62 38 63 61 31 66 39 37 2d 63 63 32 31 2d 34 31 39 65 2d 38 63 36 62 2d 35 31 65 36 34 33 63 30 65 39 39 37 } //01 00  $b8ca1f97-cc21-419e-8c6b-51e643c0e997
		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } //01 00  get_CurrentDomain
		$a_01_3 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_4 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } //01 00  CreateInstance
		$a_01_5 = {41 63 74 69 76 61 74 6f 72 } //01 00  Activator
		$a_01_6 = {47 65 74 54 79 70 65 } //00 00  GetType
	condition:
		any of ($a_*)
 
}