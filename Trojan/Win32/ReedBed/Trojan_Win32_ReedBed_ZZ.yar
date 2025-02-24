
rule Trojan_Win32_ReedBed_ZZ{
	meta:
		description = "Trojan:Win32/ReedBed.ZZ,SIGNATURE_TYPE_CMDHSTR_EXT,67 00 67 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 54 00 69 00 74 00 61 00 6e 00 50 00 6c 00 75 00 73 00 } //100 \SOFTWARE\TitanPlus
		$a_00_1 = {72 00 65 00 67 00 } //1 reg
		$a_00_2 = {20 00 61 00 64 00 64 00 20 00 } //1  add 
		$a_00_3 = {20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00 20 00 } //1  /t REG_SZ /d 
	condition:
		((#a_00_0  & 1)*100+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=103
 
}