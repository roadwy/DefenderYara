
rule Trojan_Win32_Fero_SPDB_MTB{
	meta:
		description = "Trojan:Win32/Fero.SPDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 02 00 "
		
	strings :
		$a_81_0 = {45 62 66 65 55 61 64 65 68 61 68 63 74 6b 64 61 6e } //01 00  EbfeUadehahctkdan
		$a_01_1 = {69 70 73 6f 69 61 77 65 33 33 2e 64 6c 6c } //01 00  ipsoiawe33.dll
		$a_01_2 = {45 62 66 65 55 61 64 65 68 61 68 63 74 6b 64 61 6e } //00 00  EbfeUadehahctkdan
	condition:
		any of ($a_*)
 
}