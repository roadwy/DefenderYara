
rule Trojan_Win32_Cridex_SPQ_MTB{
	meta:
		description = "Trojan:Win32/Cridex.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_81_0 = {42 6f 6e 65 62 65 67 69 6e } //01 00  Bonebegin
		$a_81_1 = {52 61 74 68 65 72 64 65 73 69 67 6e } //01 00  Ratherdesign
		$a_81_2 = {53 74 6f 6e 65 4e 75 6d 65 72 61 6c } //00 00  StoneNumeral
	condition:
		any of ($a_*)
 
}