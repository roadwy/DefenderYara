
rule Trojan_Win32_GuLoader_SUF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_81_0 = {5c 42 61 6c 6c 6f 74 65 72 65 74 2e 67 69 66 } //1 \Balloteret.gif
		$a_81_1 = {5c 61 63 71 75 65 6e 74 2e 69 6e 69 } //1 \acquent.ini
		$a_81_2 = {5c 73 74 72 61 6e 64 62 72 65 64 64 65 72 73 2e 68 74 6d } //1 \strandbredders.htm
		$a_81_3 = {5c 56 69 73 69 6f 6e 65 72 5c 70 6f 73 74 69 63 61 6c 6c 79 2e 7a 69 70 } //1 \Visioner\postically.zip
		$a_81_4 = {5c 70 72 65 74 72 65 72 6e 65 73 5c 6d 75 73 65 75 6d 73 2e 6a 70 67 } //1 \pretrernes\museums.jpg
		$a_81_5 = {65 74 68 79 6c 65 6e 69 63 61 6c 6c 79 5c 74 65 6d 62 6c 6f 72 73 2e 74 78 74 } //1 ethylenically\temblors.txt
		$a_81_6 = {5c 4d 65 61 31 37 35 2e 65 78 65 } //1 \Mea175.exe
		$a_81_7 = {5c 64 69 61 6c 6f 67 62 6f 6b 73 65 5c 6e 65 64 73 6c 61 67 74 65 64 65 2e 74 78 74 } //1 \dialogbokse\nedslagtede.txt
		$a_81_8 = {5c 75 61 72 62 65 6a 64 73 64 79 67 74 69 67 65 73 5c 67 6f 64 73 74 65 72 6d 69 6e 61 6c 65 72 6e 65 73 2e 69 6e 69 } //1 \uarbejdsdygtiges\godsterminalernes.ini
		$a_81_9 = {50 68 65 6e 6f 6d 65 6e 61 6c 69 7a 65 34 36 2e 69 6e 69 } //1 Phenomenalize46.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1+(#a_81_9  & 1)*1) >=10
 
}