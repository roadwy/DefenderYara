
rule PWS_BAT_Grmasi_YA_MTB{
	meta:
		description = "PWS:BAT/Grmasi.YA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 00 47 00 72 00 6f 00 77 00 74 00 6f 00 70 00 69 00 61 00 5c 00 73 00 61 00 76 00 65 00 2e 00 64 00 61 00 74 00 } //2 \Growtopia\save.dat
		$a_01_1 = {73 00 6d 00 74 00 70 00 2e 00 67 00 6d 00 61 00 69 00 6c 00 2e 00 63 00 6f 00 6d 00 } //2 smtp.gmail.com
		$a_01_2 = {53 00 62 00 69 00 65 00 44 00 4c 00 4c 00 2e 00 64 00 6c 00 6c 00 } //1 SbieDLL.dll
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}