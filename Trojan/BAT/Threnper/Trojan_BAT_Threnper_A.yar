
rule Trojan_BAT_Threnper_A{
	meta:
		description = "Trojan:BAT/Threnper.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 74 63 6d 69 6e 65 72 00 6d 61 69 6e 00 72 65 66 69 6c 6c 73 74 61 72 74 75 70 } //4
		$a_01_1 = {2d 00 75 00 20 00 54 00 68 00 61 00 6e 00 65 00 5f 00 54 00 68 00 61 00 6e 00 65 00 } //4 -u Thane_Thane
		$a_01_2 = {73 00 63 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 scvhost.exe
		$a_01_3 = {2d 00 6f 00 20 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 65 00 75 00 2e 00 74 00 72 00 69 00 70 00 6c 00 65 00 6d 00 69 00 6e 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 3a 00 38 00 33 00 34 00 34 00 } //1 -o http://eu.triplemining.com:8344
		$a_01_4 = {2d 00 70 00 20 00 6f 00 70 00 65 00 72 00 61 00 74 00 69 00 6f 00 6e 00 31 00 31 00 } //1 -p operation11
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}