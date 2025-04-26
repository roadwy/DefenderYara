
rule Trojan_Win32_GuLoader_SUI_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 6b 72 75 62 74 75 64 73 65 } //1 skrubtudse
		$a_81_1 = {67 6c 6f 73 73 6f 6c 61 72 79 6e 67 65 61 6c 20 68 61 6e 67 65 65 20 69 73 63 65 6e 65 73 74 74 65 } //1 glossolaryngeal hangee iscenestte
		$a_81_2 = {75 64 76 65 6a 65 72 } //1 udvejer
		$a_81_3 = {73 61 61 72 73 6b 6f 72 70 65 6e 20 78 65 6e 6f 6d 69 20 61 6e 74 69 73 70 69 72 69 74 75 61 6c 69 73 6d } //1 saarskorpen xenomi antispiritualism
		$a_81_4 = {61 66 73 67 6e 69 6e 67 65 72 6e 65 20 74 61 6b 6b 65 74 61 6c 65 72 6e 65 73 } //1 afsgningerne takketalernes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_SUI_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.SUI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {61 74 69 6f 6e 61 6c 69 74 65 74 73 6d 72 6b 65 74 5c 69 73 6f 6e 6f 6d 69 63 5c 53 75 62 74 65 72 73 75 70 65 72 6c 61 74 69 76 65 5c 56 65 68 66 74 65 74 73 5c 73 6b 79 62 61 6e 6b 65 6e 2e 65 6d 70 } //1 ationalitetsmrket\isonomic\Subtersuperlative\Vehftets\skybanken.emp
		$a_81_1 = {62 79 67 6e 69 6e 67 65 72 6e 65 73 } //1 bygningernes
		$a_81_2 = {73 6b 79 62 61 6e 6b 65 6e 2e 65 6d 70 } //1 skybanken.emp
		$a_81_3 = {73 63 72 65 61 6d 65 64 20 72 75 6d 62 61 69 6e 67 20 73 6f 6f 74 69 73 68 } //1 screamed rumbaing sootish
		$a_81_4 = {62 72 6e 64 65 6d 72 6b 6e 69 6e 67 65 72 6e 65 } //1 brndemrkningerne
		$a_81_5 = {6a 65 74 65 73 20 69 73 63 68 75 72 79 } //1 jetes ischury
		$a_81_6 = {73 65 69 73 6d 6f 6d 65 74 65 72 65 74 20 72 75 73 74 65 64 65 73 } //1 seismometeret rustedes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}
rule Trojan_Win32_GuLoader_SUI_MTB_3{
	meta:
		description = "Trojan:Win32/GuLoader.SUI!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 00 61 00 67 00 67 00 72 00 75 00 6e 00 64 00 73 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 65 00 6e 00 73 00 20 00 74 00 72 00 61 00 75 00 6d 00 61 00 74 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 } //2 baggrundsprocessens traumatologies
		$a_01_1 = {6c 00 69 00 67 00 65 00 73 00 61 00 61 00 76 00 65 00 6c 00 20 00 70 00 68 00 79 00 6c 00 6c 00 6f 00 73 00 74 00 61 00 63 00 68 00 79 00 73 00 } //2 ligesaavel phyllostachys
		$a_01_2 = {70 00 75 00 6c 00 76 00 65 00 72 00 65 00 6f 00 75 00 73 00 20 00 68 00 65 00 6c 00 62 00 72 00 65 00 64 00 73 00 67 00 72 00 75 00 6e 00 64 00 65 00 73 00 20 00 64 00 69 00 73 00 63 00 6f 00 69 00 64 00 } //2 pulvereous helbredsgrundes discoid
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}