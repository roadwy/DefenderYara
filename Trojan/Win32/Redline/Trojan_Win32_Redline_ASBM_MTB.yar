
rule Trojan_Win32_Redline_ASBM_MTB{
	meta:
		description = "Trojan:Win32/Redline.ASBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 c3 33 d8 8b d8 8b c6 8b c3 8b c3 33 f3 80 07 90 01 01 33 de 8b de 8b db 8b c6 33 c6 33 de 8b de 33 db 33 c0 f6 2f 47 e2 90 00 } //5
		$a_03_1 = {33 d8 33 f6 8b db 8b de 8b de 8b db 8b f6 8b c6 80 07 90 01 01 33 f3 33 de 33 f6 33 f3 8b db 8b f3 8b f6 8b f6 8b c3 f6 2f 47 e2 90 00 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}
rule Trojan_Win32_Redline_ASBM_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.ASBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 71 78 67 71 62 73 61 66 66 72 67 69 6b 76 76 74 76 61 64 61 71 71 62 6a 61 62 72 63 67 73 73 73 61 6b 6e 68 78 79 79 7a 6d 76 67 6e 79 77 73 } //1 hqxgqbsaffrgikvvtvadaqqbjabrcgsssaknhxyyzmvgnyws
		$a_01_1 = {72 6d 69 70 75 6d 73 64 6a 77 78 75 66 75 78 74 78 64 6e 70 78 74 68 65 71 72 6c 6e 62 6d 6a 61 69 66 77 71 6d 7a 64 6e 73 6a 6d 74 6a 77 62 6e 75 73 73 72 76 64 78 75 76 64 6f } //1 rmipumsdjwxufuxtxdnpxtheqrlnbmjaifwqmzdnsjmtjwbnussrvdxuvdo
		$a_01_2 = {69 69 6e 62 76 75 7a 74 66 72 6a 61 63 7a 6b 6a 6a 73 70 78 64 76 74 61 67 79 64 66 6d 62 69 67 6a 69 72 70 66 68 73 77 73 76 6f 6e 63 6e 6c 79 69 76 75 63 71 6c 63 69 62 68 62 66 76 68 77 7a 69 63 6e 73 67 79 70 66 78 6e } //1 iinbvuztfrjaczkjjspxdvtagydfmbigjirpfhswsvoncnlyivucqlcibhbfvhwzicnsgypfxn
		$a_01_3 = {79 6d 6d 6d 79 71 62 76 74 6c 6e 78 71 74 6e 72 6d 6c 75 64 6b 6f 68 6f 6f 64 76 78 68 65 61 67 72 6f 61 62 69 67 7a 74 66 68 6e 76 79 73 75 69 65 6d 6e 77 79 61 70 6e 6f 6d 6b 63 75 75 6e 74 } //1 ymmmyqbvtlnxqtnrmludkohoodvxheagroabigztfhnvysuiemnwyapnomkcuunt
		$a_01_4 = {73 77 69 71 7a 77 6a 71 6b 6d 6e 6b 65 70 6c 73 6b 65 6a 76 77 73 6a 7a 6d 73 77 64 7a 66 72 64 79 6f 69 72 6e 73 79 64 6e 72 6f 71 6e 68 77 62 68 61 65 68 71 77 6f 71 65 75 75 6c 72 79 74 65 } //1 swiqzwjqkmnkeplskejvwsjzmswdzfrdyoirnsydnroqnhwbhaehqwoqeuulryte
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}