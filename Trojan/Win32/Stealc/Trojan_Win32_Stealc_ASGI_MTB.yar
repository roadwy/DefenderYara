
rule Trojan_Win32_Stealc_ASGI_MTB{
	meta:
		description = "Trojan:Win32/Stealc.ASGI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 69 6c 61 67 65 6b 20 62 69 73 65 68 61 6b 75 68 69 72 61 62 61 64 61 63 6f 79 65 } //1 silagek bisehakuhirabadacoye
		$a_01_1 = {76 00 61 00 63 00 65 00 6a 00 61 00 7a 00 75 00 6c 00 75 00 66 00 61 00 70 00 65 00 73 00 75 00 } //1 vacejazulufapesu
		$a_01_2 = {56 00 61 00 6a 00 65 00 70 00 75 00 66 00 75 00 70 00 61 00 20 00 73 00 75 00 6d 00 69 00 76 00 65 00 20 00 62 00 61 00 76 00 75 00 78 00 75 00 63 00 61 00 77 00 75 00 78 00 } //1 Vajepufupa sumive bavuxucawux
		$a_01_3 = {62 00 69 00 79 00 75 00 7a 00 75 00 63 00 75 00 7a 00 65 00 6d 00 30 00 57 00 6f 00 66 00 20 00 73 00 61 00 64 00 20 00 76 00 65 00 6c 00 65 00 73 00 75 00 63 00 61 00 20 00 79 00 75 00 72 00 6f 00 74 00 75 00 74 00 61 00 76 00 61 00 76 00 65 00 63 00 75 00 67 00 20 00 6a 00 65 00 7a 00 75 00 74 00 75 00 6a 00 75 00 78 00 65 00 79 00 61 00 77 00 61 00 6a 00 } //1 biyuzucuzem0Wof sad velesuca yurotutavavecug jezutujuxeyawaj
		$a_01_4 = {4d 00 65 00 72 00 69 00 6e 00 61 00 20 00 74 00 75 00 70 00 6f 00 6d 00 20 00 62 00 69 00 6c 00 69 00 6b 00 6f 00 67 00 } //1 Merina tupom bilikog
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}