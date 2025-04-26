
rule Trojan_Win64_Reflexon_LK_MTB{
	meta:
		description = "Trojan:Win64/Reflexon.LK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 72 00 65 00 76 00 2e 00 61 00 65 00 73 00 } //1 /rev.aes
		$a_03_1 = {50 72 6f 6a 65 63 74 [0-04] 5f 42 79 70 61 73 73 48 6f 6f 6b 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 50 72 6f 6a 65 63 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}