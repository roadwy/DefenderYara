
rule Trojan_Win32_NSISInject_RPS_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {54 6a 61 6e 74 69 6e 67 2e 4d 65 6e } //1 Tjanting.Men
		$a_81_1 = {43 6f 65 6e 6f 62 6c 61 73 74 69 63 2e 69 6e 69 } //1 Coenoblastic.ini
		$a_81_2 = {42 6f 75 72 62 6f 6e 69 73 74 33 39 } //1 Bourbonist39
		$a_81_3 = {53 6f 66 74 77 61 72 65 5c 54 69 74 74 65 72 65 72 73 5c 53 61 6e 6a 61 6b 62 65 67 5c 4f 6c 69 65 66 6f 72 75 72 65 6e 65 6e 64 65 73 } //1 Software\Titterers\Sanjakbeg\Olieforurenendes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}
rule Trojan_Win32_NSISInject_RPS_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 65 72 6d 69 6e 61 62 6c 65 6e 65 73 73 37 33 2e 6c 6e 6b } //1 Terminableness73.lnk
		$a_01_1 = {62 61 67 67 72 75 6e 64 73 70 65 72 69 6f 64 65 72 } //1 baggrundsperioder
		$a_01_2 = {54 65 72 6d 6f 67 72 61 66 65 72 69 6e 67 73 } //1 Termograferings
		$a_01_3 = {46 79 6c 64 6e 69 6e 67 65 72 6e 65 73 2e 69 6e 69 } //1 Fyldningernes.ini
		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 42 61 67 73 64 65 72 79 67 6c 6e 65 6e 65 73 5c 4d 6f 74 69 6f 6e 65 6e 5c 46 6c 6f 74 65 72 31 31 36 5c 41 6e 74 6f 6c 6f 67 69 65 72 } //1 Software\Bagsderyglnenes\Motionen\Floter116\Antologier
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}