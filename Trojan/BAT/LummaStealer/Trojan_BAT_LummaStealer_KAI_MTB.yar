
rule Trojan_BAT_LummaStealer_KAI_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.KAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {59 69 6e 5a 53 75 58 6f 62 4a 71 6b 73 4a 75 70 4b 44 53 54 5a 6f } //1 YinZSuXobJqksJupKDSTZo
		$a_01_1 = {6c 5a 45 4e 78 46 50 66 64 58 43 52 64 50 56 55 47 76 68 73 4b 74 69 75 } //1 lZENxFPfdXCRdPVUGvhsKtiu
		$a_01_2 = {72 4d 49 6b 4f 4b 52 74 45 45 } //1 rMIkOKRtEE
		$a_01_3 = {64 49 5a 71 53 44 70 6b 6c 58 75 45 66 4a 67 67 50 } //1 dIZqSDpklXuEfJggP
		$a_01_4 = {4c 65 61 64 69 6e 67 20 74 68 65 20 66 75 74 75 72 65 20 6f 66 20 69 6e 74 65 67 72 61 74 65 64 20 74 65 63 68 6e 6f 6c 6f 67 79 20 73 6f 6c 75 74 69 6f 6e 73 2e } //1 Leading the future of integrated technology solutions.
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}