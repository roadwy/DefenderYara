
rule Trojan_Win32_OffLoader_ADQ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.ADQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 00 68 00 61 00 6e 00 63 00 65 00 74 00 68 00 72 00 6f 00 61 00 74 00 2e 00 69 00 63 00 75 00 2f 00 61 00 6a 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 } //3 chancethroat.icu/ajt.php?pe
		$a_01_1 = {63 00 6f 00 61 00 6c 00 63 00 72 00 69 00 6d 00 65 00 2e 00 69 00 63 00 75 00 2f 00 61 00 69 00 74 00 2e 00 70 00 68 00 70 00 3f 00 70 00 65 00 } //3 coalcrime.icu/ait.php?pe
		$a_01_2 = {2f 00 6e 00 6f 00 63 00 6f 00 6f 00 6b 00 69 00 65 00 73 00 } //1 /nocookies
		$a_01_3 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}