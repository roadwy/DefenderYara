
rule Trojan_Win32_Zenpack_MBIK_MTB{
	meta:
		description = "Trojan:Win32/Zenpack.MBIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {57 00 69 00 6d 00 61 00 64 00 69 00 6e 00 61 00 77 00 6f 00 63 00 6f 00 63 00 61 00 79 00 20 00 79 00 75 00 6a 00 75 00 79 00 75 00 6d 00 6f 00 76 00 65 00 72 00 6f 00 73 00 6f 00 } //01 00  Wimadinawococay yujuyumoveroso
		$a_01_1 = {50 00 6f 00 77 00 75 00 74 00 61 00 72 00 69 00 20 00 6b 00 75 00 68 00 61 00 67 00 69 00 6c 00 65 00 74 00 20 00 6c 00 75 00 78 00 75 00 6c 00 6f 00 79 00 69 00 68 00 } //01 00  Powutari kuhagilet luxuloyih
		$a_01_2 = {73 00 65 00 74 00 6f 00 76 00 75 00 68 00 65 00 79 00 69 00 76 00 75 00 6b 00 61 00 63 00 61 00 70 00 6f 00 6b 00 6f 00 70 00 65 00 68 00 } //01 00  setovuheyivukacapokopeh
		$a_01_3 = {68 00 69 00 77 00 61 00 74 00 69 00 63 00 61 00 79 00 6f 00 6b 00 69 00 6d 00 61 00 63 00 75 00 73 00 61 00 76 00 65 00 66 00 75 00 6a 00 69 00 } //01 00  hiwaticayokimacusavefuji
		$a_01_4 = {76 00 75 00 6a 00 65 00 66 00 65 00 76 00 6f 00 74 00 6f 00 70 00 75 00 6c 00 61 00 6b 00 6f 00 63 00 69 00 64 00 61 00 6d 00 } //00 00  vujefevotopulakocidam
	condition:
		any of ($a_*)
 
}