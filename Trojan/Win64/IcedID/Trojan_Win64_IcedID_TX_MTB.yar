
rule Trojan_Win64_IcedID_TX_MTB{
	meta:
		description = "Trojan:Win64/IcedID.TX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {7a 6e 69 62 69 6e 63 78 78 62 6b 2e 64 6c 6c } //1 znibincxxbk.dll
		$a_81_1 = {63 6e 65 72 73 6e 6a 77 66 76 68 61 67 6d 78 6c 65 } //1 cnersnjwfvhagmxle
		$a_81_2 = {65 79 68 77 6f 74 69 79 69 70 6e 61 6f 64 6b 79 } //1 eyhwotiyipnaodky
		$a_81_3 = {67 74 66 67 6e 78 61 6a 61 6d 6c 61 } //1 gtfgnxajamla
		$a_81_4 = {6b 62 64 65 6b 6d 6d 6e 62 73 77 6f 71 } //1 kbdekmmnbswoq
		$a_81_5 = {6c 6f 78 67 6a 63 6e 70 6f 78 70 6f 73 74 61 68 } //1 loxgjcnpoxpostah
		$a_81_6 = {70 71 64 78 6e 6b 65 63 72 } //1 pqdxnkecr
		$a_81_7 = {78 6f 70 6c 6a 6f 73 72 6f 70 6d 63 75 65 75 6c } //1 xopljosropmcueul
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}