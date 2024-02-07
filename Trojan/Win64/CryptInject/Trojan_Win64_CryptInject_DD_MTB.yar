
rule Trojan_Win64_CryptInject_DD_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 0a 00 00 0a 00 "
		
	strings :
		$a_01_0 = {71 6f 62 78 62 67 75 6a 37 71 65 2e 64 6c 6c } //01 00  qobxbguj7qe.dll
		$a_01_1 = {73 75 31 39 63 33 6e 36 37 30 35 30 } //01 00  su19c3n67050
		$a_01_2 = {6f 68 62 6b 39 33 35 79 31 70 } //01 00  ohbk935y1p
		$a_01_3 = {66 36 61 34 78 30 74 30 } //01 00  f6a4x0t0
		$a_01_4 = {76 35 61 65 73 7a 72 } //0a 00  v5aeszr
		$a_01_5 = {6c 74 6a 74 74 34 30 2e 64 6c 6c } //01 00  ltjtt40.dll
		$a_01_6 = {65 31 6e 71 37 6c 70 30 32 6a 6d 38 } //01 00  e1nq7lp02jm8
		$a_01_7 = {72 32 71 39 37 6d 32 37 38 6b 38 67 } //01 00  r2q97m278k8g
		$a_01_8 = {71 36 31 31 63 38 30 64 39 } //01 00  q611c80d9
		$a_01_9 = {65 36 77 61 6f 34 32 73 } //00 00  e6wao42s
	condition:
		any of ($a_*)
 
}