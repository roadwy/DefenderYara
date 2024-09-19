
rule Trojan_BAT_Redline_AMAK_MTB{
	meta:
		description = "Trojan:BAT/Redline.AMAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_80_0 = {43 63 4a 56 62 71 56 52 57 41 41 65 5a 73 4a 44 4d 4d 44 74 64 } //CcJVbqVRWAAeZsJDMMDtd  1
		$a_80_1 = {57 42 69 64 58 62 55 79 67 4b 65 6a 52 49 75 62 4e 55 58 45 6b 7a 4b 47 } //WBidXbUygKejRIubNUXEkzKG  1
		$a_80_2 = {4f 76 56 70 4e 69 73 69 67 63 4c 77 79 6c 78 6f 49 79 54 5a 72 58 5a 49 72 74 4e 47 } //OvVpNisigcLwylxoIyTZrXZIrtNG  1
		$a_80_3 = {74 6b 76 67 69 78 66 77 44 50 59 65 71 65 43 43 4c 78 4b 74 } //tkvgixfwDPYeqeCCLxKt  1
		$a_80_4 = {75 5a 75 53 71 77 47 68 51 70 4c 49 70 54 6d 6e 52 } //uZuSqwGhQpLIpTmnR  1
		$a_80_5 = {52 50 65 48 77 7a 7a 67 6b 49 50 4e 4e 47 51 74 76 48 78 6c 74 57 54 65 52 } //RPeHwzzgkIPNNGQtvHxltWTeR  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=3
 
}