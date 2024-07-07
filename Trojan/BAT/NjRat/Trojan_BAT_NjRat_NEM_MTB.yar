
rule Trojan_BAT_NjRat_NEM_MTB{
	meta:
		description = "Trojan:BAT/NjRat.NEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 06 00 00 "
		
	strings :
		$a_01_0 = {24 65 33 38 61 62 64 35 65 2d 30 35 31 63 2d 34 62 36 62 2d 62 38 32 39 2d 31 36 64 39 65 33 63 31 64 61 31 64 } //5 $e38abd5e-051c-4b6b-b829-16d9e3c1da1d
		$a_01_1 = {73 65 73 74 65 69 6d 2e 65 78 65 } //5 sesteim.exe
		$a_01_2 = {61 64 64 5f 53 68 75 74 64 6f 77 6e } //3 add_Shutdown
		$a_01_3 = {76 34 2e 30 2e 33 30 33 31 39 } //2 v4.0.30319
		$a_01_4 = {77 77 77 77 77 78 } //1 wwwwwx
		$a_01_5 = {53 53 53 53 6e } //1 SSSSn
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=17
 
}