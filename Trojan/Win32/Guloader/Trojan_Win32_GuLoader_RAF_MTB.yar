
rule Trojan_Win32_GuLoader_RAF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {25 69 73 6f 6d 65 74 72 69 25 5c 73 74 79 72 74 64 79 6b 6b 65 72 65 6e } //1 %isometri%\styrtdykkeren
		$a_81_1 = {35 5c 68 61 61 6e 64 61 72 62 65 6a 64 65 72 6e 65 73 5c 65 70 6f 78 79 65 64 2e 68 74 6d } //1 5\haandarbejdernes\epoxyed.htm
		$a_81_2 = {6c 61 6e 67 73 6f 6d 6d 65 6c 69 67 65 20 74 61 76 65 72 6e 73 20 62 61 6a 65 72 65 6e } //1 langsommelige taverns bajeren
		$a_81_3 = {73 69 65 72 73 20 64 61 74 61 74 65 6b 6e 69 6b 6b 65 72 73 } //1 siers datateknikkers
		$a_81_4 = {69 6e 66 6f 6c 64 20 64 61 65 6b 6b 65 72 2e 65 78 65 } //1 infold daekker.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_RAF_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 66 65 6a 65 6c 69 73 74 65 6e 73 5c 69 6e 67 72 6f 73 73 69 6e 67 } //1 \fejelistens\ingrossing
		$a_81_1 = {25 6d 61 6e 79 61 74 74 61 25 5c 64 69 73 70 6c 65 61 73 75 72 65 6d 65 6e 74 5c 55 6e 64 65 72 63 6c 75 74 63 68 31 39 33 } //1 %manyatta%\displeasurement\Underclutch193
		$a_81_2 = {5c 73 61 6e 64 77 69 63 68 6d 6e 64 5c 6a 65 6e 6e 65 74 73 2e 69 6e 69 } //1 \sandwichmnd\jennets.ini
		$a_81_3 = {6c 69 6e 67 65 72 65 72 20 66 6f 72 6d 61 74 6c 6e 67 64 65 73 } //1 lingerer formatlngdes
		$a_81_4 = {73 65 72 6d 6f 6e 69 6e 67 20 75 6e 69 6f 6e 73 64 61 6e 6e 65 6c 73 65 72 73 } //1 sermoning unionsdannelsers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}