
rule Trojan_BAT_Zmutzy_NX_MTB{
	meta:
		description = "Trojan:BAT/Zmutzy.NX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {54 77 6f 4c 65 76 65 6c 45 6e 75 6d 65 72 61 74 6f 72 2e 54 75 63 73 6f 6e } //1 TwoLevelEnumerator.Tucson
		$a_81_1 = {41 71 75 61 6d 69 6e 65 } //1 Aquamine
		$a_81_2 = {47 41 35 30 42 57 35 46 34 51 48 51 35 34 50 38 35 37 } //1 GA50BW5F4QHQ54P857
		$a_01_3 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //1 InvokeMember
		$a_01_4 = {4d 44 35 43 72 79 70 74 6f 53 65 72 76 69 63 65 50 72 6f 76 69 64 65 72 } //1 MD5CryptoServiceProvider
		$a_01_5 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //1 TransformFinalBlock
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}