
rule Trojan_BAT_FormBook_NMF_MTB{
	meta:
		description = "Trojan:BAT/FormBook.NMF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {32 61 35 31 64 36 32 31 2d 33 65 30 64 2d 34 32 39 33 2d 61 32 61 64 2d 39 36 34 37 32 31 62 66 66 66 37 62 } //2 2a51d621-3e0d-4293-a2ad-964721bfff7b
		$a_01_1 = {25 4a 09 61 54 09 17 62 09 1d 63 60 0d 11 06 17 58 } //1
		$a_01_2 = {1b 62 11 04 19 63 60 61 } //1 戛Б挙慠
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}