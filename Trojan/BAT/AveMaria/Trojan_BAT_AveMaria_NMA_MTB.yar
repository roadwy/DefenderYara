
rule Trojan_BAT_AveMaria_NMA_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 18 20 a2 e7 3f 61 5a 20 ?? ?? ?? a8 61 38 ?? ?? ?? ff 7e ?? ?? ?? 04 7e ?? ?? ?? 04 28 ?? ?? ?? 06 20 ?? ?? ?? 09 38 ?? ?? ?? ff 11 17 17 58 13 17 20 ?? ?? ?? 7e } //5
		$a_01_1 = {42 48 4e 68 37 37 32 } //1 BHNh772
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AveMaria_NMA_MTB_2{
	meta:
		description = "Trojan:BAT/AveMaria.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 16 0d 11 06 20 ?? ?? ?? cd 5a 20 ?? ?? ?? 34 61 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 20 ?? ?? ?? 18 28 ?? ?? ?? 2b 28 ?? ?? ?? 06 } //5
		$a_01_1 = {43 43 30 31 2e 66 72 6d 44 61 6e 68 53 61 63 68 53 61 6e 50 68 61 6d 2e 72 65 73 6f 75 72 63 65 73 } //1 CC01.frmDanhSachSanPham.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}
rule Trojan_BAT_AveMaria_NMA_MTB_3{
	meta:
		description = "Trojan:BAT/AveMaria.NMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {28 04 00 00 0a 6f ?? ?? ?? 0a 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff 73 ?? ?? ?? 0a 13 0b 20 ?? ?? ?? 00 fe ?? ?? 00 38 ?? ?? ?? ff 00 11 0b 11 01 17 73 ?? ?? ?? 0a } //5
		$a_01_1 = {51 55 4f 54 41 54 49 4f 4e 4c 49 53 54 46 4f 52 54 55 52 4b 4d 45 4e 49 53 54 41 4e 2e 44 69 63 74 69 6f 6e 61 72 69 65 73 } //1 QUOTATIONLISTFORTURKMENISTAN.Dictionaries
		$a_01_2 = {53 6c 7a 73 6d 71 61 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 Slzsmqar.Properties.Resources.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=7
 
}