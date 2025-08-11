
rule Trojan_Win32_GuLoader_RAB_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 61 6e 74 6f 6e 69 5c 4b 69 61 75 67 68 39 30 5c 73 70 69 72 61 6c 66 6a 65 64 72 65 6e 65 } //1 \antoni\Kiaugh90\spiralfjedrene
		$a_81_1 = {74 69 64 73 70 72 69 6f 72 69 74 65 72 69 6e 67 65 72 6e 65 20 61 6c 6d 65 6e 6e 79 74 74 69 67 74 20 6b 61 6e 61 77 68 61 } //1 tidsprioriteringerne almennyttigt kanawha
		$a_81_2 = {73 74 79 72 65 70 72 6f 67 72 61 6d 73 } //1 styreprograms
		$a_81_3 = {62 61 73 69 6c 69 6b 75 6d 65 6e 20 7a 61 63 68 } //1 basilikumen zach
		$a_81_4 = {73 6f 62 65 20 61 61 72 73 62 75 64 67 65 74 74 65 74 2e 65 78 65 } //1 sobe aarsbudgettet.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}