
rule Trojan_Win32_Guloader_CR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 65 61 74 61 6c 5c 53 61 6d 6d 65 6e 73 74 6e 69 6e 67 73 6c 65 64 73 5c 52 65 74 73 66 6f 72 66 6c 67 6e 69 6e 67 65 72 } //1 Meatal\Sammenstningsleds\Retsforflgninger
		$a_01_1 = {4c 62 65 67 61 6e 67 65 6e 73 25 5c 46 72 79 73 65 70 75 6e 6b 74 73 73 6e 6b 6e 69 6e 67 73 5c 70 6c 65 74 74 65 72 2e 73 6f 72 } //1 Lbegangens%\Frysepunktssnknings\pletter.sor
		$a_01_2 = {61 72 6d 61 64 61 65 72 73 5c 6c 6f 6b 61 6c 70 6c 61 6e 6f 6d 72 61 61 64 65 72 2e 69 6e 69 } //1 armadaers\lokalplanomraader.ini
		$a_01_3 = {72 65 62 75 74 74 6f 6e 69 6e 67 5c 4b 6d 70 65 73 61 6c 73 2e 70 65 72 } //1 rebuttoning\Kmpesals.per
		$a_01_4 = {68 65 6e 72 65 6a 73 65 72 73 5c 62 69 6f 67 72 61 70 68 65 72 } //1 henrejsers\biographer
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}