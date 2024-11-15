
rule Trojan_Win32_Vidar_MBXX_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MBXX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 75 77 69 6d 65 76 65 74 69 6b 61 7a 69 62 6f 77 61 62 75 63 6f 6b 75 } //2 tuwimevetikazibowabucoku
		$a_01_1 = {4a 00 75 00 64 00 75 00 6d 00 69 00 62 00 6f 00 68 00 69 00 6e 00 20 00 79 00 65 00 77 00 75 00 70 00 75 00 20 00 66 00 65 00 66 00 65 00 20 00 64 00 61 00 77 00 65 00 20 00 63 00 61 00 73 00 61 00 64 00 69 00 63 00 69 00 77 00 69 00 68 00 } //1 Judumibohin yewupu fefe dawe casadiciwih
		$a_01_2 = {52 00 69 00 79 00 6f 00 7a 00 65 00 6c 00 75 00 68 00 61 00 20 00 6d 00 75 00 72 00 75 00 6d 00 69 00 6a 00 61 00 78 00 20 00 79 00 75 00 63 00 6f 00 20 00 6d 00 69 00 63 00 6f 00 6c 00 65 00 63 00 61 00 73 00 20 00 78 00 6f 00 74 00 75 00 68 00 75 00 74 00 75 00 20 00 6b 00 6f 00 63 00 75 00 6e 00 65 00 78 00 6f 00 68 00 20 00 72 00 6f 00 66 00 75 00 6a 00 61 00 6e 00 69 00 6d 00 75 00 6d 00 69 00 6a 00 65 00 } //1 Riyozeluha murumijax yuco micolecas xotuhutu kocunexoh rofujanimumije
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}