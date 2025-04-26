
rule Trojan_Win32_GuLoader_RSD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {6b 72 65 62 61 6e 65 6e 73 5c 41 6e 74 69 61 6e 61 70 68 79 6c 61 63 74 6f 67 65 6e 31 38 } //1 krebanens\Antianaphylactogen18
		$a_81_1 = {2d 5c 61 6c 6d 61 63 65 6e 5c 66 6f 72 73 6b 61 6e 73 6e 69 6e 67 5c 61 74 74 72 69 62 75 74 76 72 64 69 74 69 6c 64 65 6c 69 6e 67 73 } //1 -\almacen\forskansning\attributvrditildelings
		$a_81_2 = {25 66 72 69 6e 67 65 72 25 5c 6d 65 74 6f 64 65 72 6e 65 5c 73 79 6d 70 68 6f 6e 69 73 74 } //1 %fringer%\metoderne\symphonist
		$a_81_3 = {39 39 5c 67 61 6c 74 72 61 70 5c 66 72 61 73 6b 72 65 76 6e 65 2e 69 6e 69 } //1 99\galtrap\fraskrevne.ini
		$a_81_4 = {6e 6f 6e 63 65 72 74 61 69 6e 74 79 5c 73 61 6e 64 61 72 74 65 72 } //1 noncertainty\sandarter
		$a_81_5 = {4d 69 6e 69 67 72 61 6e 74 73 31 35 32 2e 74 78 74 } //1 Minigrants152.txt
		$a_81_6 = {73 75 62 63 6f 6e 73 75 6c 73 68 69 70 20 62 65 67 72 61 6d 73 65 64 65 73 2e 65 78 65 } //1 subconsulship begramsedes.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}