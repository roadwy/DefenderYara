
rule Trojan_BAT_LummaStealer_E_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 16 07 16 1f 10 } //02 00  ᘈᘇဟ
		$a_01_1 = {08 16 07 1f 0f 1f 10 } //02 00 
		$a_01_2 = {09 04 16 04 8e 69 6f } //01 00 
		$a_01_3 = {52 65 73 6f 75 72 63 65 4d 61 6e 61 67 65 72 } //01 00  ResourceManager
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}