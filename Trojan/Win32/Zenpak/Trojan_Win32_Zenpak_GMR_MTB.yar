
rule Trojan_Win32_Zenpak_GMR_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 76 65 72 79 77 68 69 63 68 4c 76 65 72 79 58 61 6c 73 6f 61 } //1 everywhichLveryXalsoa
		$a_01_1 = {7a 6f 75 72 5a 63 77 68 69 63 68 51 75 } //1 zourZcwhichQu
		$a_01_2 = {66 67 69 76 65 2e 66 72 75 69 74 75 79 75 72 7a 64 } //1 fgive.fruituyurzd
		$a_01_3 = {6e 71 68 65 6e 72 6e 65 77 64 36 38 2e 64 6c 6c } //1 nqhenrnewd68.dll
		$a_01_4 = {45 61 6c 45 73 6e 65 61 74 61 79 73 78 78 74 } //1 EalEsneataysxxt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}