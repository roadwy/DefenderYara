
rule Trojan_Win32_Guloader_SPYY_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SPYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {43 00 72 00 65 00 74 00 69 00 6e 00 6f 00 75 00 73 00 31 00 35 00 5c 00 55 00 6e 00 64 00 65 00 72 00 64 00 72 00 65 00 6a 00 6e 00 69 00 6e 00 67 00 65 00 6e 00 73 00 } //1 Cretinous15\Underdrejningens
		$a_01_1 = {70 00 72 00 69 00 6e 00 74 00 70 00 72 00 6f 00 62 00 6c 00 65 00 6d 00 65 00 74 00 5c 00 64 00 6f 00 65 00 64 00 74 00 2e 00 69 00 6e 00 69 00 } //1 printproblemet\doedt.ini
		$a_01_2 = {6c 00 79 00 73 00 6b 00 6f 00 70 00 69 00 5c 00 66 00 61 00 6c 00 6c 00 6f 00 73 00 73 00 79 00 6d 00 62 00 6f 00 6c 00 65 00 74 00 2e 00 69 00 6e 00 69 00 } //1 lyskopi\fallossymbolet.ini
		$a_01_3 = {50 00 6c 00 61 00 73 00 6d 00 6f 00 67 00 61 00 6d 00 79 00 2e 00 62 00 65 00 67 00 } //1 Plasmogamy.beg
		$a_01_4 = {74 00 69 00 64 00 73 00 73 00 74 00 65 00 6d 00 70 00 6c 00 65 00 72 00 2e 00 76 00 65 00 6c 00 } //1 tidsstempler.vel
		$a_01_5 = {45 00 75 00 72 00 79 00 61 00 6c 00 65 00 2e 00 62 00 61 00 6a 00 } //1 Euryale.baj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}