
rule Trojan_Win32_Vidar_MBIP_MTB{
	meta:
		description = "Trojan:Win32/Vidar.MBIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 69 76 65 67 75 6b 69 64 6f 70 61 70 65 74 6f 64 65 6e 75 66 69 72 6f 76 61 6e 75 6b 6f } //1 pivegukidopapetodenufirovanuko
		$a_01_1 = {6c 75 79 75 63 75 63 69 68 69 7a 61 77 6f 72 75 6d 6f 6b 75 6c 69 64 6f 66 69 6b 69 20 70 65 76 65 78 69 70 69 77 61 70 69 76 6f 72 65 64 75 77 69 6b 6f 7a 6f 6a 65 6d 6f 64 61 74 20 76 75 6b 6f 63 69 6b 75 } //1 luyucucihizaworumokulidofiki pevexipiwapivoreduwikozojemodat vukociku
		$a_01_2 = {6c 65 79 69 6d 75 7a 75 62 75 63 65 64 61 62 20 79 61 64 69 6a 61 77 75 70 61 64 65 73 65 6c 69 68 65 72 6f 66 75 76 69 6e 75 74 6f 62 69 7a 69 20 76 75 6e 65 74 65 6b 69 6d 69 72 65 70 6f 67 65 78 69 63 } //1 leyimuzubucedab yadijawupadeseliherofuvinutobizi vunetekimirepogexic
		$a_01_3 = {79 6f 6e 61 78 75 6d 6f 79 20 67 61 6b 65 79 75 77 75 6a 6f 73 65 70 61 66 75 73 6f 67 69 67 61 77 65 68 65 20 66 65 6e 69 74 65 64 69 6e 75 67 61 72 65 68 69 20 77 61 76 65 64 75 6a 75 64 65 7a 75 6e 61 6e 69 6d 75 7a 65 } //1 yonaxumoy gakeyuwujosepafusogigawehe fenitedinugarehi wavedujudezunanimuze
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}