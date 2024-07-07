
rule Trojan_Win32_Fadvresh_A{
	meta:
		description = "Trojan:Win32/Fadvresh.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 6e 6f 6e 65 2e 6e 6f 6e 65 2e 6e 6f 6e 65 } //1 http://none.none.none
		$a_01_1 = {41 64 76 52 65 66 72 65 73 68 } //1 AdvRefresh
		$a_03_2 = {be 4e 02 00 00 3b d6 7e 90 01 01 8b d6 89 15 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}