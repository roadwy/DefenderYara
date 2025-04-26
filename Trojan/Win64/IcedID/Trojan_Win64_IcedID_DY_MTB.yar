
rule Trojan_Win64_IcedID_DY_MTB{
	meta:
		description = "Trojan:Win64/IcedID.DY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 4c 74 4b 67 31 47 4e 47 47 6d 41 32 4e } //10 ALtKg1GNGGmA2N
		$a_01_1 = {45 48 35 45 77 4c 6a 43 64 51 31 70 78 4d 59 79 } //1 EH5EwLjCdQ1pxMYy
		$a_01_2 = {49 6e 33 54 78 71 36 6c 56 59 73 4b 72 64 6a 33 53 66 32 } //1 In3Txq6lVYsKrdj3Sf2
		$a_01_3 = {4b 4c 36 69 33 46 41 50 48 38 33 56 63 58 } //1 KL6i3FAPH83VcX
		$a_01_4 = {4c 52 79 62 45 38 4d 30 47 4f 59 49 45 68 4d 78 50 66 36 70 39 } //1 LRybE8M0GOYIEhMxPf6p9
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}