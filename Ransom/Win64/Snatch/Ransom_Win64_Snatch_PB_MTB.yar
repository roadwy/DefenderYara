
rule Ransom_Win64_Snatch_PB_MTB{
	meta:
		description = "Ransom:Win64/Snatch.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a 20 22 69 69 75 4c 39 71 35 5a 59 72 66 6d 79 34 77 4f 46 79 69 4d 2f 4b 61 44 38 44 34 7a 73 6c 36 33 45 67 6e 66 4b 55 46 61 43 2f 32 61 73 7a 6e 67 75 72 6c 4b 61 4e 62 57 79 5a 41 6d 7a 67 2f 4f 77 58 7a 78 30 49 71 51 69 71 6e 77 6b 56 79 69 68 47 72 } //10 Go build ID: "iiuL9q5ZYrfmy4wOFyiM/KaD8D4zsl63EgnfKUFaC/2aszngurlKaNbWyZAmzg/OwXzx0IqQiqnwkVyihGr
		$a_01_1 = {61 74 20 20 66 70 3d 20 69 73 20 20 6c 72 3a 20 6f 66 20 20 6f 6e 20 20 70 63 3d 20 73 70 3a 20 73 70 3d } //1 at  fp= is  lr: of  on  pc= sp: sp=
		$a_01_2 = {6d 61 69 6e 2e 72 61 6e 73 6f 6d 4e 6f 74 65 } //1 main.ransomNote
		$a_01_3 = {68 74 74 70 2e 68 74 74 70 32 43 6c 69 65 6e 74 43 6f 6e 6e } //1 http.http2ClientConn
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=13
 
}