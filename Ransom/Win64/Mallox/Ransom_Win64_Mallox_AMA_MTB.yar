
rule Ransom_Win64_Mallox_AMA_MTB{
	meta:
		description = "Ransom:Win64/Mallox.AMA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 64 61 74 61 20 68 61 73 20 62 65 65 6e 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //1 Your data has been stolen and encrypted
		$a_01_1 = {57 65 20 77 69 6c 6c 20 64 65 6c 65 74 65 20 74 68 65 20 73 74 6f 6c 65 6e 20 64 61 74 61 20 61 6e 64 20 68 65 6c 70 20 77 69 74 68 20 74 68 65 20 72 65 63 6f 76 65 72 79 20 6f 66 20 65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 20 61 66 74 65 72 20 70 61 79 6d 65 6e 74 20 68 61 73 20 62 65 65 6e 20 6d 61 64 65 } //1 We will delete the stolen data and help with the recovery of encrypted files after payment has been made
		$a_01_2 = {44 6f 20 6e 6f 74 20 74 72 79 20 74 6f 20 63 68 61 6e 67 65 20 6f 72 20 72 65 73 74 6f 72 65 20 66 69 6c 65 73 20 79 6f 75 72 73 65 6c 66 2c 20 74 68 69 73 20 77 69 6c 6c 20 62 72 65 61 6b 20 74 68 65 6d } //1 Do not try to change or restore files yourself, this will break them
		$a_01_3 = {57 65 20 70 72 6f 76 69 64 65 20 66 72 65 65 20 64 65 63 72 79 70 74 69 6f 6e 20 66 6f 72 20 61 6e 79 20 33 20 66 69 6c 65 73 20 75 70 20 74 6f 20 33 4d 42 20 69 6e 20 73 69 7a 65 20 6f 6e 20 6f 75 72 20 77 65 62 73 69 74 65 } //1 We provide free decryption for any 3 files up to 3MB in size on our website
		$a_01_4 = {52 75 6e 20 54 4f 52 20 62 72 6f 77 73 65 72 20 61 6e 64 20 6f 70 65 6e 20 74 68 65 20 73 69 74 65 3a 20 77 74 79 61 66 6a 79 68 77 71 72 67 6f 34 61 34 35 77 64 76 76 77 68 65 6e 33 63 78 34 65 75 69 65 37 33 71 76 6c 68 6b 68 76 6c 72 65 78 6c 6a 6f 79 75 6b 6c 61 61 64 2e 6f 6e 69 6f 6e 2f 6d 61 6c 6c 6f 78 2f 70 72 69 76 61 74 65 53 69 67 6e 69 6e } //1 Run TOR browser and open the site: wtyafjyhwqrgo4a45wdvvwhen3cx4euie73qvlhkhvlrexljoyuklaad.onion/mallox/privateSignin
		$a_01_5 = {74 00 61 00 72 00 67 00 65 00 74 00 69 00 6e 00 66 00 6f 00 2e 00 74 00 78 00 74 00 } //1 targetinfo.txt
		$a_01_6 = {64 00 65 00 6c 00 65 00 74 00 65 00 20 00 73 00 68 00 61 00 64 00 6f 00 77 00 73 00 20 00 2f 00 61 00 6c 00 6c 00 20 00 2f 00 71 00 75 00 69 00 65 00 74 00 } //1 delete shadows /all /quiet
		$a_01_7 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 52 00 61 00 63 00 63 00 69 00 6e 00 65 00 } //1 SOFTWARE\Raccine
		$a_01_8 = {53 00 59 00 53 00 54 00 45 00 4d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 45 00 76 00 65 00 6e 00 74 00 4c 00 6f 00 67 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 52 00 61 00 63 00 63 00 69 00 6e 00 65 00 } //1 SYSTEM\CurrentControlSet\Services\EventLog\Application\Raccine
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}