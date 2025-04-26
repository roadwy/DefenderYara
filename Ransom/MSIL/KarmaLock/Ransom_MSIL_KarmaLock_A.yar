
rule Ransom_MSIL_KarmaLock_A{
	meta:
		description = "Ransom:MSIL/KarmaLock.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {22 4b 61 72 6d 61 20 44 65 63 72 79 70 74 6f 72 22 20 73 6f 66 74 77 61 72 65 } //1 "Karma Decryptor" software
		$a_01_1 = {6b 61 72 6d 61 20 52 61 6e 73 6f 6d 77 61 72 65 } //1 karma Ransomware
		$a_01_2 = {2f 78 55 73 65 72 2e 70 68 70 3f 75 73 65 72 3d } //1 /xUser.php?user=
		$a_01_3 = {23 20 44 45 43 52 59 50 54 20 4d 59 20 46 49 4c 45 53 20 23 2e 68 74 6d 6c } //1 # DECRYPT MY FILES #.html
		$a_03_4 = {6b 61 72 6d 61 [0-0f] 2e 6f 6e 69 6f 6e 2f 78 31 32 33 34 } //1
		$a_01_5 = {26 74 72 79 3d 31 26 73 74 61 74 75 73 3d 30 00 } //1 琦祲ㄽ猦慴畴㵳0
		$a_01_6 = {57 69 6e 64 6f 77 73 54 75 6e 65 55 70 2e 52 65 73 6f 75 72 63 65 73 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}