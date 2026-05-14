
rule Trojan_Win32_GuLoader_SWF_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.SWF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {5c 4d 61 6c 61 63 6f 73 74 72 61 63 6f 75 73 33 31 5c 56 69 6e 74 65 72 62 6c 65 31 37 31 2e 6c 6e 6b } //1 \Malacostracous31\Vinterble171.lnk
		$a_81_1 = {5c 66 6f 6e 64 65 6e 73 2e 62 6c 76 } //1 \fondens.blv
		$a_81_2 = {49 73 6f 63 79 74 69 63 2e 74 78 74 } //1 Isocytic.txt
		$a_81_3 = {5c 55 6e 64 74 6f 67 65 73 5c 6b 75 6c 74 75 72 6a 6f 75 72 6e 61 6c 69 73 74 69 6b 2e 4e 6f 6e } //1 \Undtoges\kulturjournalistik.Non
		$a_81_4 = {5c 4d 69 6c 6c 69 6f 6e 65 72 6e 65 5c 41 66 73 74 76 6e 69 6e 67 65 72 2e 63 61 72 } //1 \Millionerne\Afstvninger.car
		$a_81_5 = {5c 73 74 72 6f 67 65 6e 65 5c 73 79 73 74 65 6d 74 79 70 65 6e 2e 6b 6f 73 } //1 \strogene\systemtypen.kos
		$a_81_6 = {5c 42 61 6d 62 75 73 74 70 70 65 74 73 5c 73 74 69 6e 75 73 5c 63 61 70 65 72 73 6f 6d 65 6e 65 73 73 } //1 \Bambustppets\stinus\capersomeness
		$a_81_7 = {5c 68 6d 6f 73 74 61 73 65 2e 6b 6f 6d } //1 \hmostase.kom
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}