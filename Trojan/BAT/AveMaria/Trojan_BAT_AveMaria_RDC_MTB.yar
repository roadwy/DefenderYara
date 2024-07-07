
rule Trojan_BAT_AveMaria_RDC_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {33 33 30 39 63 61 65 38 2d 63 64 33 63 2d 34 63 64 31 2d 62 32 32 63 2d 36 64 39 32 30 32 31 31 63 38 61 34 } //1 3309cae8-cd3c-4cd1-b22c-6d920211c8a4
		$a_01_1 = {43 68 69 54 69 65 74 50 68 69 65 75 54 68 75 65 } //1 ChiTietPhieuThue
		$a_01_2 = {66 72 6d 42 61 6e 67 44 69 61 } //1 frmBangDia
		$a_01_3 = {51 75 61 6e 4c 79 42 61 6e 67 44 69 61 43 44 } //1 QuanLyBangDiaCD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}