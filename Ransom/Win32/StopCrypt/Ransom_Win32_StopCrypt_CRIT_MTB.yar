
rule Ransom_Win32_StopCrypt_CRIT_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.CRIT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 65 70 75 6a 6f 62 } //01 00  Bepujob
		$a_01_1 = {6c 65 6e 61 7a 6f 68 65 68 69 72 6f 20 72 75 70 75 67 65 67 6f 78 75 7a 65 76 6f 79 61 6b 75 72 75 68 69 77 20 63 61 70 6f 62 69 67 75 20 63 65 6d 75 68 69 74 75 74 69 68 69 76 61 74 75 73 6f 63 61 63 61 67 65 64 75 63 61 79 69 68 65 } //01 00  lenazohehiro rupugegoxuzevoyakuruhiw capobigu cemuhitutihivatusocacageducayihe
		$a_01_2 = {62 6f 68 61 78 61 76 75 77 65 64 75 } //01 00  bohaxavuwedu
		$a_01_3 = {42 61 67 65 6e 69 66 75 74 65 } //00 00  Bagenifute
	condition:
		any of ($a_*)
 
}