
rule Ransom_Win64_Tuga_YAQ_MTB{
	meta:
		description = "Ransom:Win64/Tuga.YAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 04 00 00 "
		
	strings :
		$a_01_0 = {66 0f 6e c2 66 0f fc d0 66 0f 6e 01 0f 57 d0 66 0f 7e 11 8d 47 04 66 0f 6e d8 66 0f 70 db 00 66 0f fe dd 66 0f 6f cb 66 0f 62 cb 66 0f 38 28 cc 66 0f 6f c3 66 0f 6a c3 } //1
		$a_01_1 = {66 0f 67 d2 66 0f 6e c2 66 0f fc d0 66 0f 6e 41 04 0f 57 d0 66 0f 7e 51 04 83 c7 08 48 8d 49 08 } //1
		$a_01_2 = {7a 58 5b 58 56 67 18 16 6d 78 13 14 0f 21 6b 13 } //10 塺塛杖ᘘ硭ᐓℏ፫
		$a_01_3 = {79 59 54 59 55 66 1f 17 6e 79 6c 15 0c 20 6c 12 } //10
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=12
 
}