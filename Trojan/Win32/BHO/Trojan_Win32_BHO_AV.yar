
rule Trojan_Win32_BHO_AV{
	meta:
		description = "Trojan:Win32/BHO.AV,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 73 74 61 6c 6c 00 5c 74 6f 64 6f 2e 65 78 65 } //5
		$a_01_1 = {68 74 74 70 3a 2f 2f 34 2e 67 75 7a 68 69 6a 69 6a 69 6e 2e 63 6f 6d } //5 http://4.guzhijijin.com
		$a_01_2 = {71 71 73 68 65 6c 00 00 72 65 67 2e 64 61 74 } //1
		$a_01_3 = {33 36 30 75 70 00 00 00 72 65 67 2e 64 61 74 } //1
		$a_01_4 = {52 61 76 4d 6f 6e 53 00 73 6f 6e 69 2e 65 78 65 } //1 慒䵶湯S潳楮攮數
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}