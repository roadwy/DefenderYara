
rule Trojan_BAT_XenoRat_SG_MTB{
	meta:
		description = "Trojan:BAT/XenoRat.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 75 63 6b 6f 6f 6d 6f 6e 2e 64 6c 6c } //1 cuckoomon.dll
		$a_01_1 = {58 00 65 00 6e 00 6f 00 55 00 70 00 64 00 61 00 74 00 65 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00 } //1 XenoUpdateManager
		$a_01_2 = {2f 00 71 00 75 00 65 00 72 00 79 00 20 00 2f 00 76 00 20 00 2f 00 66 00 6f 00 20 00 63 00 73 00 76 00 } //1 /query /v /fo csv
		$a_01_3 = {78 00 65 00 6e 00 6f 00 20 00 72 00 61 00 74 00 20 00 63 00 6c 00 69 00 65 00 6e 00 74 00 2e 00 65 00 78 00 65 00 } //1 xeno rat client.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}