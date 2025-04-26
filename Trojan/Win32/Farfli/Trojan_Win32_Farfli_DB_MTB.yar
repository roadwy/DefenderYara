
rule Trojan_Win32_Farfli_DB_MTB{
	meta:
		description = "Trojan:Win32/Farfli.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 90 58 60 40 00 32 d1 88 90 58 60 40 00 40 3d d3 e0 00 00 7c } //3
		$a_01_1 = {76 00 62 00 63 00 66 00 67 00 2e 00 69 00 6e 00 69 00 } //1 vbcfg.ini
		$a_01_2 = {43 00 3a 00 5c 00 31 00 2e 00 6a 00 70 00 67 00 } //1 C:\1.jpg
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}