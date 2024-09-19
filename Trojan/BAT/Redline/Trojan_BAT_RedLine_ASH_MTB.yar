
rule Trojan_BAT_RedLine_ASH_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ASH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 6b 69 6e 48 4f 56 4b 77 50 6c 45 6d 71 75 5a 52 4f 69 4c 59 62 4e 51 } //1 hkinHOVKwPlEmquZROiLYbNQ
		$a_01_1 = {55 4e 42 59 4f 75 4a 72 74 4d 48 72 54 4e 63 6b 79 6d 52 67 72 4e 74 62 6c 4e 4b 62 63 } //1 UNBYOuJrtMHrTNckymRgrNtblNKbc
		$a_01_2 = {50 4e 4c 79 57 4d 4b 43 50 72 49 49 79 78 61 5a 78 61 45 50 65 4a 7a 42 56 51 77 4e 4d } //1 PNLyWMKCPrIIyxaZxaEPeJzBVQwNM
		$a_01_3 = {63 61 69 75 41 56 44 58 4e 53 6c 4e 74 6d 6a 53 5a 74 43 68 5a 69 65 70 76 77 7a 78 41 } //1 caiuAVDXNSlNtmjSZtChZiepvwzxA
		$a_01_4 = {24 65 33 64 32 66 38 61 39 2d 62 37 63 35 2d 34 61 32 33 2d 38 64 31 32 2d 36 35 34 33 32 61 62 63 64 65 39 30 } //1 $e3d2f8a9-b7c5-4a23-8d12-65432abcde90
		$a_01_5 = {50 00 75 00 73 00 68 00 69 00 6e 00 67 00 20 00 74 00 68 00 65 00 20 00 62 00 6f 00 75 00 6e 00 64 00 61 00 72 00 69 00 65 00 73 00 20 00 6f 00 66 00 20 00 74 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 79 00 20 00 66 00 6f 00 72 00 20 00 61 00 20 00 62 00 72 00 69 00 67 00 68 00 74 00 65 00 72 00 20 00 74 00 6f 00 6d 00 6f 00 72 00 72 00 6f 00 77 00 } //1 Pushing the boundaries of technology for a brighter tomorrow
		$a_03_6 = {43 00 6f 00 73 00 6d 00 69 00 63 00 45 00 64 00 67 00 65 00 [0-22] 00 2e 00 65 00 78 00 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=7
 
}