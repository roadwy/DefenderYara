
rule Trojan_Win64_Bazarcrypt_GA_MTB{
	meta:
		description = "Trojan:Win64/Bazarcrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {41 03 c5 99 41 [0-02] 0f b6 [0-04] 41 [0-02] 4c [0-02] 41 02 [0-04] 41 88 [0-04] 0f b6 c1 88 4c [0-02] 41 0f b6 [0-04] 03 c1 99 41 f7 [0-02] 48 63 [0-02] 49 03 [0-02] 0f b6 [0-02] 41 02 [0-02] 41 32 [0-04] 48 [0-02] 01 88 4e [0-02] 74 [0-08] eb } //5
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //LoadResource  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}