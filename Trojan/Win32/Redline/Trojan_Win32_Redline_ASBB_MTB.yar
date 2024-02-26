
rule Trojan_Win32_Redline_ASBB_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 65 6b 75 7a 75 6d 6f 77 6f 72 61 66 6f 79 65 78 61 76 75 6d 65 78 69 } //01 00  fekuzumoworafoyexavumexi
		$a_01_1 = {64 75 77 75 7a 65 66 69 66 61 6d 6f 77 65 78 65 73 61 76 65 73 6f 78 75 7a } //01 00  duwuzefifamowexesavesoxuz
		$a_01_2 = {62 6f 74 69 6c 75 70 69 6e 6f 7a 6f 7a 69 6a 61 73 6f 77 75 72 75 6b 75 73 61 77 61 64 6f } //01 00  botilupinozozijasowurukusawado
		$a_01_3 = {72 69 78 65 66 61 76 61 70 75 78 6f 72 6f 6c 69 6b 61 63 61 70 61 79 69 7a 69 66 69 76 } //01 00  rixefavapuxorolikacapayizifiv
		$a_01_4 = {6d 75 70 65 79 69 6d 69 70 6f 62 61 6d 61 78 65 6b 6f 79 61 67 65 6a 6f 77 75 } //01 00  mupeyimipobamaxekoyagejowu
		$a_01_5 = {66 00 61 00 6c 00 69 00 6c 00 65 00 74 00 69 00 78 00 69 00 64 00 65 00 70 00 75 00 68 00 6f 00 70 00 69 00 66 00 65 00 20 00 79 00 61 00 6e 00 75 00 64 00 6f 00 6a 00 61 00 6d 00 6f 00 63 00 20 00 62 00 69 00 6e 00 20 00 72 00 6f 00 74 00 69 00 63 00 65 00 73 00 75 00 78 00 65 00 6c 00 69 00 68 00 65 00 6b 00 69 00 67 00 65 00 70 00 69 00 64 00 } //00 00  faliletixidepuhopife yanudojamoc bin roticesuxelihekigepid
	condition:
		any of ($a_*)
 
}