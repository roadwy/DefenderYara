
rule Trojan_Win64_Bazarcrypt_GA_MTB{
	meta:
		description = "Trojan:Win64/Bazarcrypt.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_02_0 = {41 03 c5 99 41 90 02 02 0f b6 90 02 04 41 90 02 02 4c 90 02 02 41 02 90 02 04 41 88 90 02 04 0f b6 c1 88 4c 90 02 02 41 0f b6 90 02 04 03 c1 99 41 f7 90 02 02 48 63 90 02 02 49 03 90 02 02 0f b6 90 02 02 41 02 90 02 02 41 32 90 02 04 48 90 02 02 01 88 4e 90 02 02 74 90 02 08 eb 90 00 } //5
		$a_80_1 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 } //GetCurrentProcess  1
		$a_80_2 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 } //LoadResource  1
	condition:
		((#a_02_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=7
 
}