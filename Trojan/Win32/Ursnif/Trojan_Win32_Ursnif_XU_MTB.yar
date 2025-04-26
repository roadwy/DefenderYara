
rule Trojan_Win32_Ursnif_XU_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.XU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {47 72 65 6d 61 20 4b 61 72 67 6f } //1 Grema Kargo
		$a_81_1 = {61 64 6d 69 6e 40 67 72 65 6d 61 6f 6e 6c 69 6e 65 2e 72 75 } //1 admin@gremaonline.ru
		$a_81_2 = {72 65 77 67 71 72 77 67 2e 70 64 62 } //1 rewgqrwg.pdb
		$a_81_3 = {6d 4a 5f 6b 34 58 6a } //1 mJ_k4Xj
		$a_81_4 = {5a 48 59 36 79 } //1 ZHY6y
		$a_81_5 = {32 48 2b 37 7a 2a 55 31 } //1 2H+7z*U1
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}