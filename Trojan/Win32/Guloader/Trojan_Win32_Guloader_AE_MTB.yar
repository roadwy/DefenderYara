
rule Trojan_Win32_Guloader_AE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_81_0 = {73 65 67 75 65 6e 64 6f 2e 69 6e 69 } //2 seguendo.ini
		$a_81_1 = {70 6f 6c 65 6d 69 63 69 73 69 6e 67 2e 69 6e 69 } //2 polemicising.ini
		$a_81_2 = {43 72 61 62 6c 69 6b 65 2e 66 6f 72 } //2 Crablike.for
		$a_81_3 = {73 61 62 62 61 74 73 61 66 74 65 6e 73 2e 6a 70 67 } //2 sabbatsaftens.jpg
		$a_81_4 = {54 65 61 62 6f 78 65 73 5c 68 65 70 74 61 70 6c 6f 69 64 79 } //2 Teaboxes\heptaploidy
		$a_81_5 = {6d 65 67 61 6e 74 68 72 6f 70 75 73 5c 61 72 69 65 74 74 61 } //2 meganthropus\arietta
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2) >=12
 
}