
rule Trojan_Win32_Guloader_CD_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 0d 00 00 "
		
	strings :
		$a_01_0 = {64 79 62 6b 6c 65 64 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 74 65 6b 73 74 6e 69 6e 67 65 6e 5c 4d 69 6c 69 65 75 65 72 6e 65 73 5c 42 69 6f 6c 6f 67 69 6b 6c 61 73 73 65 72 5c 73 63 72 61 6d 62 } //1 dybklede\Uninstall\tekstningen\Milieuernes\Biologiklasser\scramb
		$a_01_1 = {74 65 6c 6f 62 6c 61 73 74 69 63 2e 73 6b 72 } //1 teloblastic.skr
		$a_01_2 = {77 61 72 6d 65 72 73 5c 41 65 72 6f 70 61 75 73 65 31 31 30 2e 74 69 6e } //1 warmers\Aeropause110.tin
		$a_01_3 = {66 72 69 63 74 69 6f 6e 70 72 6f 6f 66 25 5c 53 6c 61 76 65 62 75 6e 64 65 74 36 32 } //1 frictionproof%\Slavebundet62
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 45 71 75 69 6c 6f 62 61 74 65 5c 73 70 72 69 6e 67 77 6f 72 74 5c 62 65 74 72 6f 72 5c 62 6f 62 6c 65 6b 61 6d 6d 65 72 73 } //1 Software\Equilobate\springwort\betror\boblekammers
		$a_01_5 = {63 69 6d 6e 65 6c 5c 70 6c 61 73 68 79 2e 64 6c 6c } //1 cimnel\plashy.dll
		$a_01_6 = {48 61 6c 6c 6d 6f 6f 74 5c 41 6d 69 64 6f 6e 65 5c 53 65 78 62 6f 6d 62 65 73 5c 74 65 78 74 61 72 69 61 6e } //1 Hallmoot\Amidone\Sexbombes\textarian
		$a_01_7 = {55 6e 72 65 76 65 72 62 65 72 61 6e 74 5c 55 6e 70 65 72 6a 75 72 69 6e 67 39 31 5c 55 6e 74 72 6f 63 68 61 69 63 5c 42 72 61 74 74 69 6e 67 73 62 6f 72 67 } //1 Unreverberant\Unperjuring91\Untrochaic\Brattingsborg
		$a_01_8 = {52 65 64 75 70 6c 69 6b 61 74 69 6f 6e 5c 4c 69 67 67 65 64 61 67 65 31 30 35 5c 48 69 6b 6b 65 74 73 5c 56 61 72 69 61 62 65 6c 65 72 6b 6c 72 69 6e 67 65 72 } //1 Reduplikation\Liggedage105\Hikkets\Variabelerklringer
		$a_01_9 = {50 68 6f 6e 6f 70 68 6f 72 65 2e 72 61 74 } //1 Phonophore.rat
		$a_01_10 = {47 65 6e 6e 65 6d 62 72 75 64 73 6b 72 66 74 65 72 6e 65 73 5c 66 65 6d 6b 61 6e 74 73 2e 6c 6e 6b } //1 Gennembrudskrfternes\femkants.lnk
		$a_01_11 = {64 6a 76 6c 65 6b 75 6c 74 65 6e 5c 6b 6f 6e 64 65 6e 73 61 74 6f 72 65 72 6e 65 2e 76 69 72 } //1 djvlekulten\kondensatorerne.vir
		$a_01_12 = {42 75 64 62 72 69 6e 67 65 72 65 6e 2e 61 61 64 } //1 Budbringeren.aad
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1) >=6
 
}