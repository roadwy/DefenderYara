
rule Trojan_BAT_QuasarRat_NEAG_MTB{
	meta:
		description = "Trojan:BAT/QuasarRat.NEAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 04 00 00 "
		
	strings :
		$a_01_0 = {0a 06 17 6f 2a 00 00 0a 06 18 6f 2b 00 00 0a 06 03 04 6f 2c 00 00 0a 0b 07 02 16 02 8e 69 6f 2d 00 00 0a 0c 07 6f 2e 00 00 0a 06 6f 2f 00 00 0a 08 2a } //10
		$a_01_1 = {61 00 6d 00 73 00 69 00 2e 00 64 00 6c 00 6c 00 } //2 amsi.dll
		$a_01_2 = {73 65 74 5f 43 72 65 61 74 65 4e 6f 57 69 6e 64 6f 77 } //2 set_CreateNoWindow
		$a_01_3 = {70 61 79 6c 6f 61 64 2e 65 78 65 } //2 payload.exe
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=16
 
}