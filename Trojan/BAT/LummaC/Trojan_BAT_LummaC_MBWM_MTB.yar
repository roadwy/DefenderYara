
rule Trojan_BAT_LummaC_MBWM_MTB{
	meta:
		description = "Trojan:BAT/LummaC.MBWM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {9c 07 08 04 08 05 5d 91 9c 08 17 58 0c 08 20 00 01 00 00 } //1
		$a_01_1 = {49 39 55 64 6a 77 44 00 44 51 6a 62 43 67 64 44 61 4d 4d 56 4e 64 45 47 4b 6b } //2 㥉摕睪D兄扪权䑤䵡噍摎䝅歋
		$a_01_2 = {47 33 44 77 64 32 33 00 6c 6c 78 69 4f 39 4d 6a 72 41 49 6d 77 63 68 68 4f 65 } //2 ㍇睄㉤3汬楸㥏橍䅲浉捷桨敏
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=3
 
}