
rule Trojan_BAT_Kuhaname_A{
	meta:
		description = "Trojan:BAT/Kuhaname.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6a 65 63 74 00 24 49 52 36 2d 31 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //1 湉敪瑣␀剉ⴶ1彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟
		$a_01_1 = {67 65 74 5f 55 73 65 72 4e 61 6d 65 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //1 敧彴獕牥慎敭开彟彟彟彟彟彟彟彟彟彟
		$a_01_2 = {44 65 73 69 67 6e 65 72 47 65 6e 65 72 61 74 65 64 41 74 74 72 69 62 75 74 65 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //1 敄楳湧牥敇敮慲整䅤瑴楲畢整开彟彟彟彟彟彟彟彟彟彟彟彟彟
		$a_01_3 = {4d 79 47 72 6f 75 70 43 6f 6c 6c 65 63 74 69 6f 6e 41 74 74 72 69 62 75 74 65 00 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //1 祍片畯䍰汯敬瑣潩䅮瑴楲畢整开彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟彟
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}