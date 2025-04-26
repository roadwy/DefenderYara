
rule Trojan_Win64_ClipBanker_RA_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 6c 74 65 6b 2e 65 78 65 } //1 Realtek.exe
		$a_01_1 = {28 62 63 31 29 5b 61 2d 7a 41 2d 48 4a 2d 4e 50 2d 5a 30 2d 39 5d 7b 33 39 7d 24 } //1 (bc1)[a-zA-HJ-NP-Z0-9]{39}$
		$a_01_2 = {62 6e 62 31 5b 30 2d 39 61 2d 7a 41 2d 5a 5d 7b 33 38 7d 24 29 } //1 bnb1[0-9a-zA-Z]{38}$)
		$a_01_3 = {6c 74 63 31 5b 30 2d 39 41 2d 7a 5d 7b 33 39 7d 24 29 } //1 ltc1[0-9A-z]{39}$)
		$a_01_4 = {61 64 64 72 31 71 5b 30 2d 39 61 2d 7a 41 2d 5a 5d 7b 39 37 7d } //1 addr1q[0-9a-zA-Z]{97}
		$a_01_5 = {63 6f 73 6d 6f 73 31 5b 30 2d 39 61 2d 7a 41 2d 5a 5d 7b 33 38 7d 24 29 } //1 cosmos1[0-9a-zA-Z]{38}$)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}