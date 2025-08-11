
rule Trojan_Win32_GuLoader_CCJZ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.CCJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 4c 61 6e 64 65 70 6c 61 67 65 72 35 32 2e 54 65 6b } //2 \Landeplager52.Tek
		$a_81_1 = {54 72 6f 6e 65 73 2e 6a 70 67 } //1 Trones.jpg
		$a_81_2 = {65 78 74 65 6e 73 6f 2e 69 6e 69 } //1 extenso.ini
		$a_81_3 = {70 72 69 61 63 61 6e 74 68 69 64 61 65 2e 6a 70 67 } //1 priacanthidae.jpg
		$a_81_4 = {5c 56 61 6e 64 6c 69 64 65 6e 64 65 2e 52 75 67 } //1 \Vandlidende.Rug
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=6
 
}