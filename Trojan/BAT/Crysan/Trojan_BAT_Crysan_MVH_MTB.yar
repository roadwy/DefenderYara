
rule Trojan_BAT_Crysan_MVH_MTB{
	meta:
		description = "Trojan:BAT/Crysan.MVH!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 72 74 4b 65 79 6c 6f 61 67 67 61 72 } //2 StartKeyloaggar
		$a_01_1 = {68 6f 6f 6b 49 44 } //1 hookID
		$a_01_2 = {44 65 63 72 79 70 74 42 79 74 65 73 } //1 DecryptBytes
		$a_01_3 = {41 63 74 69 76 61 74 65 50 6f 6e 67 } //1 ActivatePong
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}