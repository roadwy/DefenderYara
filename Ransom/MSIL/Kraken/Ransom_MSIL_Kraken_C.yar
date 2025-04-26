
rule Ransom_MSIL_Kraken_C{
	meta:
		description = "Ransom:MSIL/Kraken.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4b 72 61 6b 65 6e 20 43 72 79 70 74 6f 72 } //1 Kraken Cryptor
		$a_01_1 = {6f 6e 69 6f 6e 68 65 6c 70 40 6d 65 6d 65 77 61 72 65 2e 6e 65 74 } //1 onionhelp@memeware.net
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}