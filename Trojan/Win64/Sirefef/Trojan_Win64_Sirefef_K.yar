
rule Trojan_Win64_Sirefef_K{
	meta:
		description = "Trojan:Win64/Sirefef.K,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 05 00 00 "
		
	strings :
		$a_03_0 = {29 43 e5 98 48 c1 ?? 08 ff 15 } //10
		$a_01_1 = {63 6e 71 61 7a 77 73 78 65 64 63 72 66 76 74 67 65 61 62 79 68 6e 75 6a 6d 69 6b 6f 69 6a 6c 70 } //10 cnqazwsxedcrfvtgeabyhnujmikoijlp
		$a_01_2 = {6e 65 77 2f 6c 69 6e 6b 73 2e 70 68 70 } //1 new/links.php
		$a_01_3 = {70 2f 74 61 73 6b 32 2e 70 68 70 } //1 p/task2.php
		$a_01_4 = {47 45 54 20 2f 25 75 3f 77 3d 25 75 26 69 3d 25 75 26 76 3d } //1 GET /%u?w=%u&i=%u&v=
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=20
 
}
rule Trojan_Win64_Sirefef_K_2{
	meta:
		description = "Trojan:Win64/Sirefef.K,SIGNATURE_TYPE_ARHSTR_EXT,15 00 14 00 05 00 00 "
		
	strings :
		$a_03_0 = {29 43 e5 98 48 c1 ?? 08 ff 15 } //10
		$a_01_1 = {63 6e 71 61 7a 77 73 78 65 64 63 72 66 76 74 67 65 61 62 79 68 6e 75 6a 6d 69 6b 6f 69 6a 6c 70 } //10 cnqazwsxedcrfvtgeabyhnujmikoijlp
		$a_01_2 = {6e 65 77 2f 6c 69 6e 6b 73 2e 70 68 70 } //1 new/links.php
		$a_01_3 = {70 2f 74 61 73 6b 32 2e 70 68 70 } //1 p/task2.php
		$a_01_4 = {47 45 54 20 2f 25 75 3f 77 3d 25 75 26 69 3d 25 75 26 76 3d } //1 GET /%u?w=%u&i=%u&v=
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=20
 
}