
rule Trojan_Win32_Guloader_CT_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {70 69 65 74 65 74 73 68 65 6e 73 79 6e 65 6e 65 2e 64 6c 6c } //1 pietetshensynene.dll
		$a_81_1 = {45 6d 62 61 72 6b 6d 65 6e 74 5c 4c 6f 76 62 65 73 74 65 6d 6d 65 6c 73 65 72 6e 65 35 39 } //1 Embarkment\Lovbestemmelserne59
		$a_81_2 = {6d 65 73 65 6e 6e 61 5c 67 75 6e 62 61 72 72 65 6c 2e 69 6e 69 } //1 mesenna\gunbarrel.ini
		$a_81_3 = {70 6f 6c 79 6d 69 63 72 6f 62 69 61 6c 5c 50 61 70 70 65 6e 33 33 2e 6d 75 72 } //1 polymicrobial\Pappen33.mur
		$a_81_4 = {68 65 78 65 6e 65 5c 65 72 68 76 65 72 76 73 76 65 6a 6c 65 64 6e 69 6e 67 65 72 6e 65 2e 64 6c 6c } //1 hexene\erhvervsvejledningerne.dll
		$a_81_5 = {49 6d 70 65 72 61 6c 69 73 74 69 73 6b 5c 53 74 6a 70 6c 61 67 65 73 2e 74 61 72 } //1 Imperalistisk\Stjplages.tar
		$a_81_6 = {73 61 75 63 65 6e 5c 68 65 6c 68 65 64 65 72 6e 65 5c 62 65 66 61 6c 69 6e 67 65 72 6e 65 73 } //1 saucen\helhederne\befalingernes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}