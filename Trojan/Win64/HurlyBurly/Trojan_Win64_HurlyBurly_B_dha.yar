
rule Trojan_Win64_HurlyBurly_B_dha{
	meta:
		description = "Trojan:Win64/HurlyBurly.B!dha,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {69 c0 83 00 00 00 0f be d2 48 ff c1 03 c2 0f b6 11 84 d2 } //2
		$a_01_1 = {00 73 36 34 2e 64 6c 6c 00 } //1
		$a_01_2 = {00 73 33 32 2e 64 6c 6c 00 } //1
		$a_01_3 = {00 73 6b 69 6e 5f 6d 61 69 6e 00 } //2
		$a_01_4 = {00 73 6b 69 6e 5f 61 74 74 61 63 68 00 } //2
		$a_01_5 = {00 73 6b 69 6e 5f 69 6e 73 74 61 6c 6c 00 } //2 猀楫彮湩瑳污l
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2) >=5
 
}