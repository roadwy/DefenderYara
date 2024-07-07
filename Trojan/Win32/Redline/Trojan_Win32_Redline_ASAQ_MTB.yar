
rule Trojan_Win32_Redline_ASAQ_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {69 69 66 79 72 64 66 78 72 62 75 7a 64 64 6b 70 61 6d 63 69 67 6b 73 78 68 68 79 71 6d 6d 76 73 75 78 61 6e 68 69 6e 67 78 62 76 69 6e 74 6d 7a 76 62 78 62 65 6d 70 70 68 77 71 64 66 67 70 74 75 79 6f 69 79 66 78 6a } //1 iifyrdfxrbuzddkpamcigksxhhyqmmvsuxanhingxbvintmzvbxbempphwqdfgptuyoiyfxj
		$a_01_1 = {73 65 69 72 67 6b 78 6e 78 66 78 72 74 7a 75 6e 65 74 6f 7a 76 68 66 62 62 70 69 6d 79 79 73 78 78 70 64 76 68 77 73 64 61 72 62 76 63 62 7a 64 68 79 78 70 75 68 79 69 6b 71 73 68 77 74 61 6f 75 77 6a 64 6c 6c 65 63 75 62 69 65 6b 74 6a 63 6a 77 6d 70 70 } //1 seirgkxnxfxrtzunetozvhfbbpimyysxxpdvhwsdarbvcbzdhyxpuhyikqshwtaouwjdllecubiektjcjwmpp
		$a_01_2 = {6d 6f 6e 75 68 75 78 71 6f 71 65 74 6a 72 62 79 66 7a 69 62 78 76 6d 7a 62 70 65 75 77 69 6d 75 6a 66 76 62 7a 6c 64 64 68 68 63 79 6c 66 67 65 75 69 65 74 } //1 monuhuxqoqetjrbyfzibxvmzbpeuwimujfvbzlddhhcylfgeuiet
		$a_01_3 = {63 6e 75 66 62 76 6b 79 6d 6f 64 7a 72 6f 6e 73 6c 68 6c 6b 79 78 69 79 67 7a 67 6d 63 77 79 63 69 61 78 70 63 67 69 65 78 79 66 75 75 73 67 77 62 61 71 } //1 cnufbvkymodzronslhlkyxiygzgmcwyciaxpcgiexyfuusgwbaq
		$a_01_4 = {66 75 72 66 72 76 6c 76 62 7a 65 65 6b 71 71 66 75 65 76 6e 7a 72 73 74 66 69 74 67 61 74 64 6a 6e 7a 75 68 6a 61 75 68 72 7a 6a 79 6b 73 69 79 65 73 70 6c 64 } //1 furfrvlvbzeekqqfuevnzrstfitgatdjnzuhjauhrzjyksiyespld
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}