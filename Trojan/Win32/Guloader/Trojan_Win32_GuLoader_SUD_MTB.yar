
rule Trojan_Win32_GuLoader_SUD_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 53 61 64 64 65 6c 74 61 67 73 31 38 33 } //1 \Saddeltags183
		$a_81_1 = {5c 53 6f 76 65 70 6f 73 65 72 5c 62 72 79 73 74 68 75 6c 65 2e 74 78 74 } //1 \Soveposer\brysthule.txt
		$a_81_2 = {5c 47 72 75 73 67 72 61 76 65 31 39 31 5c 61 66 67 69 66 74 73 6f 72 64 6e 69 6e 67 65 72 6e 65 73 2e 7a 69 70 } //1 \Grusgrave191\afgiftsordningernes.zip
		$a_81_3 = {50 79 72 61 6d 69 64 65 6c 6c 61 2e 65 6e 6a } //1 Pyramidella.enj
		$a_81_4 = {53 65 6e 74 69 6e 65 6c 6c 69 6e 67 2e 6f 63 63 } //1 Sentinelling.occ
		$a_81_5 = {62 65 74 69 6e 67 65 64 65 2e 70 65 61 } //1 betingede.pea
		$a_81_6 = {5c 54 75 72 62 6f 6a 65 74 74 65 72 6e 65 73 31 32 39 5c 73 61 6e 65 72 69 6e 67 73 70 6c 61 6e 65 72 2e 7a 69 70 } //1 \Turbojetternes129\saneringsplaner.zip
		$a_81_7 = {5c 62 65 6d 75 73 65 64 5c 68 61 6c 69 63 6f 74 } //1 \bemused\halicot
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}