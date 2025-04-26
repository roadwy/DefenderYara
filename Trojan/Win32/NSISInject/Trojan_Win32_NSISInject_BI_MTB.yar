
rule Trojan_Win32_NSISInject_BI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4c 65 76 65 72 69 6e 67 73 74 69 64 73 70 75 6e 6b 74 5c 44 62 65 66 6f 6e 74 65 72 6e 65 73 5c 53 65 78 65 6e 6e 69 61 6c 32 33 30 5c 4d 61 63 72 6f 70 68 61 67 65 2e 69 6e 69 } //1 Leveringstidspunkt\Dbefonternes\Sexennial230\Macrophage.ini
		$a_01_1 = {45 6e 74 72 65 63 6f 74 65 73 5c 4e 65 75 74 72 61 6c 69 73 65 72 69 6e 67 73 61 6e 6c 67 67 65 74 73 5c 44 69 73 77 6f 6e 74 2e 53 63 68 } //1 Entrecotes\Neutraliseringsanlggets\Diswont.Sch
		$a_01_2 = {42 6f 6d 73 74 72 6b 74 5c 56 6f 67 6e 62 6a 72 6e 2e 69 6e 69 } //1 Bomstrkt\Vognbjrn.ini
		$a_01_3 = {53 6b 79 64 6b 6b 65 73 5c 73 65 6b 75 6e 64 61 76 61 72 65 72 6e 65 5c 64 69 73 73 65 6e 74 65 64 } //1 Skydkkes\sekundavarerne\dissented
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 73 70 6c 69 66 66 5c 50 61 61 73 61 65 74 6e 69 6e 67 5c 62 69 6f 74 6f 70 65 73 } //1 Software\spliff\Paasaetning\biotopes
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 53 61 6e 61 74 6f 72 69 65 74 5c 53 74 65 6d 6e 69 6e 67 73 62 6c 67 65 72 73 5c 49 6e 61 6e 69 6d 61 74 65 6e 65 73 73 65 73 } //1 Software\Sanatoriet\Stemningsblgers\Inanimatenesses
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}