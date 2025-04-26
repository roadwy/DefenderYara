
rule Trojan_Win32_Guloader_AB_MTB{
	meta:
		description = "Trojan:Win32/Guloader.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 "
		
	strings :
		$a_81_0 = {64 65 72 69 6d 65 6c 6c 65 6d 2e 69 6e 69 } //2 derimellem.ini
		$a_81_1 = {53 6e 6f 72 65 6c 6f 66 74 73 2e 73 61 6d } //2 Snorelofts.sam
		$a_81_2 = {73 74 72 69 64 73 6d 6e 64 65 6e 65 2e 6a 70 67 } //2 stridsmndene.jpg
		$a_81_3 = {6f 76 65 72 66 79 6c 64 74 65 5c 73 6c 61 76 65 70 65 6e } //2 overfyldte\slavepen
		$a_81_4 = {75 64 76 69 72 6b 6e 69 6e 67 65 72 5c 50 68 69 6c 6f 73 6f 70 68 65 72 73 68 69 70 } //2 udvirkninger\Philosophership
		$a_81_5 = {70 6f 6c 79 73 6f 6d 61 74 69 63 2e 74 78 74 } //2 polysomatic.txt
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2+(#a_81_3  & 1)*2+(#a_81_4  & 1)*2+(#a_81_5  & 1)*2) >=12
 
}