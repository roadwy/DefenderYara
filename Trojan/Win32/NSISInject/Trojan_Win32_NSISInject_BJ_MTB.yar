
rule Trojan_Win32_NSISInject_BJ_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.BJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 78 62 6f 6d 62 65 72 6e 65 5c 49 6e 74 65 72 66 69 72 6d 5c 45 78 68 69 62 69 74 69 6f 6e 69 73 74 2e 55 6e 69 } //1 Sexbomberne\Interfirm\Exhibitionist.Uni
		$a_01_1 = {48 65 6e 73 79 67 6e 65 5c 41 64 6a 75 6e 6b 74 75 72 65 72 36 36 5c 4f 76 65 72 63 6f 6d 70 65 6e 73 61 74 6f 72 73 5c 53 6f 75 62 72 65 74 74 65 73 2e 48 65 6c } //1 Hensygne\Adjunkturer66\Overcompensators\Soubrettes.Hel
		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 45 73 63 72 6f 77 73 5c 4a 6f 6e 67 6c 65 72 65 74 5c 42 72 65 76 64 75 65 72 } //1 Software\Escrows\Jongleret\Brevduer
		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 76 61 6e 6e 75 73 5c 41 67 69 74 61 74 65 73 36 36 5c 47 61 73 74 72 6f 73 74 61 78 69 73 5c 67 72 69 6c 6c 61 64 65 64 } //1 Software\vannus\Agitates66\Gastrostaxis\grilladed
		$a_01_4 = {54 69 74 6f 69 73 74 65 6e 5c 54 6f 69 6c 65 74 72 79 31 36 30 5c 43 6f 66 66 69 6e 6d 61 6b 65 72 2e 6c 6e 6b } //1 Titoisten\Toiletry160\Coffinmaker.lnk
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}