
rule Trojan_BAT_Blinerarch_AZ{
	meta:
		description = "Trojan:BAT/Blinerarch.AZ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {5c 00 61 00 72 00 63 00 68 00 69 00 76 00 65 00 2e 00 78 00 6d 00 6c 00 } //1 \archive.xml
		$a_00_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 37 00 37 00 2e 00 32 00 32 00 31 00 2e 00 31 00 34 00 39 00 2e 00 32 00 31 00 39 00 2f 00 } //1 http://77.221.149.219/
		$a_00_2 = {44 3a 5c 49 6e 73 74 61 6c 6c 5c 55 6d 65 6e 61 74 6f 72 5c 50 50 53 5c } //1 D:\Install\Umenator\PPS\
		$a_02_3 = {5c 5f 5a 69 70 41 72 63 68 69 76 65 90 02 03 5c 72 65 73 5c 74 65 6d 70 5c 70 61 63 6b 65 64 2e 70 64 62 90 00 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1) >=3
 
}