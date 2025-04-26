
rule Trojan_BAT_Sorcanges_A{
	meta:
		description = "Trojan:BAT/Sorcanges.A,SIGNATURE_TYPE_PEHSTR,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 72 61 6e 67 65 2e 65 78 65 } //10 orange.exe
		$a_01_1 = {6f 00 72 00 61 00 6e 00 67 00 65 00 74 00 65 00 67 00 68 00 61 00 6c 00 } //10 orangeteghal
		$a_01_2 = {4d 00 69 00 76 00 65 00 20 00 4e 00 61 00 72 00 65 00 6e 00 67 00 69 00 } //10 Mive Narengi
		$a_01_3 = {4d 00 50 00 52 00 45 00 53 00 53 00 } //10 MPRESS
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}