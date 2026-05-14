
rule Trojan_BAT_ClipBanker_SN_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {53 79 73 74 65 6d 54 65 78 74 50 72 6f 63 65 73 73 6f 72 2e 65 78 65 } //1 SystemTextProcessor.exe
		$a_81_1 = {53 79 73 74 65 6d 54 65 78 74 50 72 6f 63 65 73 73 6f 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 SystemTextProcessor.Properties.Resources.resources
		$a_81_2 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //1 SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_81_3 = {62 63 31 71 73 39 68 37 79 78 34 74 64 6a 66 6c 61 64 78 66 35 74 68 67 73 73 65 6b 37 6b 67 78 7a 35 68 32 68 61 38 73 6d 70 } //1 bc1qs9h7yx4tdjfladxf5thgssek7kgxz5h2ha8smp
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}