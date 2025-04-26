
rule Trojan_BAT_DcRat_NEA_MTB{
	meta:
		description = "Trojan:BAT/DcRat.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 70 45 6e 75 6d 4d 6f 6e 69 6b 65 72 } //1 ppEnumMoniker
		$a_01_1 = {36 35 39 35 62 36 34 31 34 34 63 63 66 31 64 66 } //1 6595b64144ccf1df
		$a_01_2 = {43 6f 6e 66 75 73 65 72 45 78 20 76 31 2e 30 2e 30 } //1 ConfuserEx v1.0.0
		$a_01_3 = {55 00 6d 00 56 00 6a 00 5a 00 57 00 6c 00 32 00 5a 00 57 00 51 00 3d 00 } //1 UmVjZWl2ZWQ=
		$a_01_4 = {59 00 57 00 31 00 7a 00 61 00 53 00 35 00 6b 00 62 00 47 00 77 00 3d 00 } //1 YW1zaS5kbGw=
		$a_01_5 = {4d 00 53 00 41 00 53 00 43 00 75 00 69 00 2e 00 65 00 78 00 65 00 } //1 MSASCui.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}