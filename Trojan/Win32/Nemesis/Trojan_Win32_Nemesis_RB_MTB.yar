
rule Trojan_Win32_Nemesis_RB_MTB{
	meta:
		description = "Trojan:Win32/Nemesis.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 72 6d 6c 6b 65 6e 73 2e 41 6c 62 } //1 Surmlkens.Alb
		$a_01_1 = {53 61 6d 66 75 6e 64 73 61 6e 73 76 61 72 2e 6c 6e 6b } //1 Samfundsansvar.lnk
		$a_01_2 = {44 72 65 69 64 65 6c 73 2e 53 74 61 } //1 Dreidels.Sta
		$a_01_3 = {43 6f 65 6e 6f 62 69 74 65 2e 64 6c 6c } //1 Coenobite.dll
		$a_01_4 = {55 6e 64 65 72 73 6f 65 67 65 6c 73 65 2e 4b 75 6e } //1 Undersoegelse.Kun
		$a_01_5 = {53 6f 66 74 77 61 72 65 5c 52 65 66 6c 65 6b 73 66 72 69 65 73 5c 4f 75 74 6c 6f 74 } //1 Software\Refleksfries\Outlot
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}