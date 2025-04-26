
rule Trojan_BAT_LummaC_AZ_MTB{
	meta:
		description = "Trojan:BAT/LummaC.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {5a 43 6e 77 51 79 75 63 7a 48 4e 56 5a 73 4c 62 56 66 61 4e 74 41 75 4b 2e 64 6c 6c } //1 ZCnwQyuczHNVZsLbVfaNtAuK.dll
		$a_81_1 = {56 47 46 6d 6a 50 52 45 79 57 45 73 62 6a 48 6d 65 48 65 62 51 63 51 41 6d 4a } //1 VGFmjPREyWEsbjHmeHebQcQAmJ
		$a_81_2 = {4c 63 72 56 61 43 56 57 6d 51 62 4e 47 65 50 4b 58 51 76 46 74 56 79 70 } //1 LcrVaCVWmQbNGePKXQvFtVyp
		$a_81_3 = {59 73 6f 6f 4d 58 70 47 4d 69 46 77 76 79 62 74 71 48 49 6b 61 54 52 64 43 } //1 YsooMXpGMiFwvybtqHIkaTRdC
		$a_81_4 = {63 54 6e 58 48 7a 46 45 6c 66 53 55 4a 78 49 74 62 77 5a 6f 73 44 4a 58 41 73 72 } //1 cTnXHzFElfSUJxItbwZosDJXAsr
		$a_81_5 = {50 66 64 78 55 4b 44 56 73 6d 48 47 66 66 53 65 77 49 72 54 62 4b 52 6c 2e 64 6c 6c } //1 PfdxUKDVsmHGffSewIrTbKRl.dll
		$a_81_6 = {58 63 44 76 62 6b 51 6e 46 78 56 4b 74 55 4b 5a 75 77 4a 47 79 74 48 41 2e 64 6c 6c } //1 XcDvbkQnFxVKtUKZuwJGytHA.dll
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}