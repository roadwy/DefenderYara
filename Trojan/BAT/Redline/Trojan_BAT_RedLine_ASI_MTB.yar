
rule Trojan_BAT_RedLine_ASI_MTB{
	meta:
		description = "Trojan:BAT/RedLine.ASI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {77 57 52 52 78 59 72 62 4b 46 78 4a 51 75 46 57 6a 4b 6a 4f 70 62 2e 64 6c 6c } //1 wWRRxYrbKFxJQuFWjKjOpb.dll
		$a_01_1 = {51 77 73 4b 54 6f 7a 68 53 50 50 45 58 67 4f 44 52 4e 59 53 78 6a 4a 2e 64 6c 6c } //1 QwsKTozhSPPEXgODRNYSxjJ.dll
		$a_01_2 = {4e 75 70 77 61 4d 52 63 4b 43 76 6a 50 6b 70 75 45 70 63 69 4d 48 52 66 } //1 NupwaMRcKCvjPkpuEpciMHRf
		$a_01_3 = {77 53 45 41 51 4c 79 6c 53 42 59 6f 70 41 70 66 55 74 72 79 58 54 4d 48 77 5a 2e 64 6c 6c } //1 wSEAQLylSBYopApfUtryXTMHwZ.dll
		$a_01_4 = {7a 45 70 4b 67 57 5a 55 6f 62 72 61 67 65 4b 63 } //1 zEpKgWZUobrageKc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}