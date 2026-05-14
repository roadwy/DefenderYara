
rule Trojan_Win32_Guloader_SJ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {70 75 6e 63 74 75 72 65 73 20 73 74 6f 72 73 74 64 65 72 73 20 6d 69 63 72 6f 6d 68 6f } //1 punctures storstders micromho
		$a_81_1 = {62 61 6e 65 64 72 69 66 74 73 5c 76 69 65 74 63 6f 6e 67 65 72 73 } //1 banedrifts\vietcongers
		$a_81_2 = {75 72 74 69 6c 73 74 61 6e 64 65 73 20 73 70 6f 72 69 63 69 64 65 2e 65 78 65 } //1 urtilstandes sporicide.exe
		$a_81_3 = {74 79 6e 64 65 64 65 73 2e 67 75 61 } //1 tyndedes.gua
		$a_81_4 = {73 71 75 69 6e 74 79 2e 6d 69 73 } //1 squinty.mis
		$a_81_5 = {73 6b 69 73 6d 61 74 69 6b 65 72 2e 75 6e 63 } //1 skismatiker.unc
		$a_81_6 = {66 6f 72 74 72 79 64 65 6c 73 65 73 70 61 72 61 67 72 61 66 66 65 72 6e 65 2e 61 73 73 } //1 fortrydelsesparagrafferne.ass
		$a_81_7 = {69 6e 74 65 72 65 73 73 65 6f 6d 72 61 61 64 65 2e 6e 69 70 } //1 interesseomraade.nip
		$a_81_8 = {6b 6f 6d 69 6b 65 72 65 73 2e 70 72 65 } //1 komikeres.pre
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}
rule Trojan_Win32_Guloader_SJ_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {47 75 69 64 65 6c 69 6e 65 73 32 30 30 2e 66 6c 6f } //1 Guidelines200.flo
		$a_81_1 = {62 61 6c 6c 65 6c 73 73 65 72 73 2e 64 72 6f } //1 ballelssers.dro
		$a_81_2 = {66 72 61 73 74 64 74 5c 6f 72 74 68 6f 74 6f 6e 65 5c 73 74 75 72 64 69 65 73 74 } //1 frastdt\orthotone\sturdiest
		$a_81_3 = {5c 6b 61 70 69 74 6c 62 61 61 6e 64 5c 55 6c 74 72 61 72 65 6c 69 67 69 6f 75 73 31 2e 6c 6e 6b } //1 \kapitlbaand\Ultrareligious1.lnk
		$a_81_4 = {73 75 6d 6d 61 72 69 73 74 5c 62 79 72 67 65 5c 53 75 67 67 65 73 74 69 76 65 73 31 31 37 } //1 summarist\byrge\Suggestives117
		$a_81_5 = {72 65 63 6f 72 64 65 64 6c 79 5c 70 61 72 6b 67 73 74 65 72 73 5c 73 61 76 76 79 } //1 recordedly\parkgsters\savvy
		$a_81_6 = {5c 64 75 72 61 74 69 76 69 73 6b 2e 7a 69 70 } //1 \durativisk.zip
		$a_81_7 = {63 6f 67 6e 61 63 67 6c 61 73 73 65 6e 65 5c 73 74 72 79 67 65 72 75 6c 6c 65 72 6e 65 73 } //1 cognacglassene\strygerullernes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}