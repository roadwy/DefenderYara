
rule Trojan_BAT_AsyncRat_NEBH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRat.NEBH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6f 74 66 75 73 63 61 74 65 64 5c 43 72 79 70 74 6f 4f 62 66 75 73 63 61 74 6f 72 5f 4f 75 74 70 75 74 5c 76 34 2e 70 64 62 } //5 Dotfuscated\CryptoObfuscator_Output\v4.pdb
		$a_01_1 = {63 63 35 64 37 38 62 38 39 61 66 38 31 62 34 33 31 37 33 63 30 35 34 36 61 31 64 32 65 36 35 61 36 } //2 cc5d78b89af81b43173c0546a1d2e65a6
		$a_01_2 = {63 61 36 30 34 31 33 32 34 35 38 64 65 35 39 33 34 37 64 63 30 36 62 63 62 62 31 66 64 37 62 66 33 } //2 ca604132458de59347dc06bcbb1fd7bf3
		$a_01_3 = {76 34 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //2 v4.Resources.resources
		$a_01_4 = {44 65 62 75 67 67 65 72 48 69 64 64 65 6e 41 74 74 72 69 62 75 74 65 } //1 DebuggerHiddenAttribute
		$a_01_5 = {44 65 62 75 67 67 69 6e 67 4d 6f 64 65 73 } //1 DebuggingModes
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=13
 
}