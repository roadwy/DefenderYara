
rule Trojan_Win32_GuLoader_NG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6b 6c 61 73 73 69 66 69 6b 61 74 69 6f 6e 65 6e 2e 53 75 72 } //1 klassifikationen.Sur
		$a_01_1 = {6d 65 64 69 61 74 69 76 65 5c 70 72 69 6f 72 69 74 65 74 65 72 6e 65 5c 73 6d 75 67 6c 69 6e 67 73 } //1 mediative\prioriteterne\smuglings
		$a_01_2 = {62 65 6b 6c 61 67 65 73 2e 6c 6e 6b } //1 beklages.lnk
		$a_01_3 = {42 65 73 61 65 74 74 65 72 5c 50 72 6f 70 61 67 61 6e 64 69 73 6d 2e 45 6e 73 } //1 Besaetter\Propagandism.Ens
		$a_01_4 = {62 61 73 73 65 74 74 65 72 6e 65 73 2e 66 6f 72 } //1 bassetternes.for
		$a_01_5 = {43 72 61 63 6b 65 72 62 65 72 72 79 } //1 Crackerberry
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule Trojan_Win32_GuLoader_NG_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {75 70 73 74 61 79 2e 66 61 63 } //1 upstay.fac
		$a_01_1 = {73 65 70 74 65 6e 61 72 69 69 5c 70 65 6c 73 62 65 72 65 64 65 72 5c 73 61 6d 6d 65 6e 66 61 74 6e 69 6e 67 65 6e } //1 septenarii\pelsbereder\sammenfatningen
		$a_01_2 = {73 75 64 65 72 6e 65 2e 66 61 73 } //1 suderne.fas
		$a_01_3 = {73 74 72 61 74 69 66 69 63 65 72 65 6e 64 65 73 2e 68 65 6e } //1 stratificerendes.hen
		$a_01_4 = {50 61 72 74 61 6b 65 72 31 39 35 2e 65 73 74 } //1 Partaker195.est
		$a_01_5 = {6d 65 72 69 6e 6f 75 6c 64 2e 6d 6f 6e } //1 merinould.mon
		$a_01_6 = {66 72 61 61 64 73 65 72 69 65 72 6e 65 2e 72 69 70 } //1 fraadserierne.rip
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule Trojan_Win32_GuLoader_NG_MTB_3{
	meta:
		description = "Trojan:Win32/GuLoader.NG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 00 6e 00 64 00 73 00 74 00 74 00 65 00 6c 00 73 00 65 00 72 00 6e 00 65 00 73 00 20 00 75 00 6e 00 64 00 65 00 72 00 6c 00 62 00 65 00 6e 00 64 00 65 00 73 00 20 00 62 00 6c 00 65 00 63 00 69 00 64 00 65 00 72 00 65 00 } //2 undsttelsernes underlbendes blecidere
		$a_01_1 = {63 00 61 00 73 00 61 00 6e 00 6f 00 76 00 61 00 20 00 73 00 75 00 62 00 62 00 6f 00 6f 00 6b 00 6b 00 65 00 65 00 70 00 65 00 72 00 } //2 casanova subbookkeeper
		$a_01_2 = {68 00 61 00 75 00 73 00 74 00 72 00 75 00 6d 00 20 00 77 00 61 00 73 00 69 00 72 00 } //2 haustrum wasir
		$a_01_3 = {64 00 79 00 62 00 64 00 65 00 70 00 73 00 79 00 6b 00 6f 00 6c 00 6f 00 67 00 73 00 20 00 64 00 6f 00 6c 00 6b 00 74 00 69 00 64 00 20 00 75 00 72 00 69 00 6e 00 76 00 65 00 6a 00 73 00 73 00 79 00 67 00 64 00 6f 00 6d 00 6d 00 65 00 6e 00 73 00 } //1 dybdepsykologs dolktid urinvejssygdommens
		$a_01_4 = {62 00 65 00 73 00 65 00 6a 00 6c 00 65 00 64 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //1 besejledes.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=8
 
}