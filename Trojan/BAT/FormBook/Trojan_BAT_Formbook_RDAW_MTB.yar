
rule Trojan_BAT_Formbook_RDAW_MTB{
	meta:
		description = "Trojan:BAT/Formbook.RDAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {65 31 31 31 35 65 39 63 2d 33 30 32 66 2d 34 33 38 39 2d 61 32 37 39 2d 39 35 64 65 61 33 30 35 36 31 30 36 } //2 e1115e9c-302f-4389-a279-95dea3056106
		$a_01_1 = {45 53 53 55 73 65 72 43 68 61 6e 67 65 72 } //2 ESSUserChanger
		$a_01_2 = {62 69 73 68 6f 70 54 72 61 6e 73 66 6f 72 6d } //1 bishopTransform
		$a_01_3 = {68 6f 72 73 65 54 72 61 6e 73 66 6f 72 6d } //1 horseTransform
		$a_01_4 = {6b 69 6e 67 49 6e 43 68 65 63 6b } //1 kingInCheck
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=7
 
}