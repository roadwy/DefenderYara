
rule Trojan_Win32_Graftor_SEFT_MTB{
	meta:
		description = "Trojan:Win32/Graftor.SEFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 00 69 00 74 00 69 00 73 00 69 00 6d 00 69 00 75 00 6d 00 69 00 73 00 6c 00 69 00 6d 00 61 00 } //2 titisimiumislima
		$a_01_1 = {6a 00 6f 00 73 00 70 00 6c 00 6f 00 76 00 69 00 73 00 6d 00 69 00 75 00 7a 00 69 00 6c 00 61 00 6d 00 61 00 } //2 josplovismiuzilama
		$a_01_2 = {64 00 61 00 7a 00 61 00 62 00 6f 00 72 00 61 00 76 00 69 00 6d 00 6e 00 61 00 73 00 76 00 65 00 } //2 dazaboravimnasve
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}