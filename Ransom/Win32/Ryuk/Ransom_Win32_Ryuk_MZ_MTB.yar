
rule Ransom_Win32_Ryuk_MZ_MTB{
	meta:
		description = "Ransom:Win32/Ryuk.MZ!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 77 00 77 00 77 00 2e 00 74 00 6f 00 72 00 70 00 72 00 6f 00 6a 00 65 00 63 00 74 00 } //1 http://www.torproject
		$a_01_1 = {2a 48 45 4c 50 5f 59 4f 55 52 5f 46 49 4c 45 53 2a } //1 *HELP_YOUR_FILES*
		$a_01_2 = {43 00 52 00 59 00 50 00 54 00 4f 00 57 00 41 00 4c 00 4c 00 } //1 CRYPTOWALL
		$a_01_3 = {6d 00 61 00 72 00 6b 00 65 00 74 00 63 00 72 00 79 00 70 00 74 00 6f 00 70 00 61 00 72 00 74 00 6e 00 65 00 72 00 73 00 2e 00 63 00 6f 00 6d 00 } //1 marketcryptopartners.com
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}