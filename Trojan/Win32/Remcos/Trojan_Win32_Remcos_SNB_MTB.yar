
rule Trojan_Win32_Remcos_SNB_MTB{
	meta:
		description = "Trojan:Win32/Remcos.SNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5c 74 72 65 6d 6d 65 73 74 6f 6c 65 6e 65 5c 66 75 67 65 6d 61 73 73 65 73 } //1 \tremmestolene\fugemasses
		$a_81_1 = {5c 69 73 74 68 6d 5c 73 75 70 65 72 73 70 68 65 6e 6f 69 64 5c 62 61 72 67 65 64 2e 69 6e 69 } //1 \isthm\supersphenoid\barged.ini
		$a_81_2 = {5c 70 61 6c 65 6f 67 65 6f 6c 6f 67 69 63 5c 66 6f 72 6d 73 74 6f 66 5c 6d 6f 73 6b 6b 68 65 72 6e 65 73 5c 2a 2e 62 69 6e } //1 \paleogeologic\formstof\moskkhernes\*.bin
		$a_81_3 = {5c 67 75 6c 73 5c 74 6f 72 73 69 6f 6e 73 5c 4a 75 73 74 69 74 73 6d 69 6e 69 73 74 65 72 69 65 72 73 2e 67 69 66 } //1 \guls\torsions\Justitsministeriers.gif
		$a_81_4 = {5c 76 67 61 76 69 73 65 6e 5c 69 6e 74 65 72 63 65 70 74 61 62 6c 65 5c 65 70 61 63 72 69 64 61 63 65 6f 75 73 2e 64 6c 6c } //1 \vgavisen\interceptable\epacridaceous.dll
		$a_81_5 = {5c 6b 61 6e 61 61 6e 69 73 6b 5c 4b 61 6d 70 65 6e 65 73 5c 74 68 77 61 72 74 73 2e 67 69 66 } //1 \kanaanisk\Kampenes\thwarts.gif
		$a_81_6 = {4c 61 6d 70 61 64 65 64 72 6f 6d 79 2e 64 64 65 } //1 Lampadedromy.dde
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}