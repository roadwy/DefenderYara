
rule TrojanDownloader_O97M_EncDoc_PDM_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PDM!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 76 61 6c 28 27 7d 2b 25 5e 29 2b 25 5e 22 2b 25 5e 32 2b 25 5e 35 2b 25 5e 2e 2b 25 5e 38 2b 25 5e 35 2b 25 5e 2e 2b 25 5e 39 2b 25 5e 31 2b 25 5e 2e 2b 25 5e 33 2b 25 5e 32 2b 25 5e 2f 2b 25 5e 2f 2b 25 5e 3a 2b 25 5e 70 2b 25 5e 74 2b 25 5e 74 2b 25 5e 68 } //1 eval('}+%^)+%^"+%^2+%^5+%^.+%^8+%^5+%^.+%^9+%^1+%^.+%^3+%^2+%^/+%^/+%^:+%^p+%^t+%^t+%^h
		$a_01_1 = {22 2b 25 5e 72 2b 25 5e 65 2b 25 5e 6c 2b 25 5e 6c 2b 25 5e 61 2b 25 5e 74 2b 25 5e 73 2b 25 5e 6e 2b 25 5e 49 2b 25 5e 2e 2b 25 5e 72 2b 25 5e 65 2b 25 5e 6c 2b 25 5e 6c 2b 25 5e 61 2b 25 5e 74 2b 25 5e 73 2b 25 5e 6e 2b 25 5e 49 2b 25 5e 73 2b 25 5e 77 2b 25 5e 6f 2b 25 5e 64 2b 25 5e 6e 2b 25 5e 69 2b 25 5e 57 2b 25 5e 22 } //1 "+%^r+%^e+%^l+%^l+%^a+%^t+%^s+%^n+%^I+%^.+%^r+%^e+%^l+%^l+%^a+%^t+%^s+%^n+%^I+%^s+%^w+%^o+%^d+%^n+%^i+%^W+%^"
		$a_01_2 = {68 2b 25 5e 74 2b 25 5e 69 2b 25 5e 77 27 2e 73 70 6c 69 74 28 27 2b 25 5e 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 } //1 h+%^t+%^i+%^w'.split('+%^').reverse().join('')
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}