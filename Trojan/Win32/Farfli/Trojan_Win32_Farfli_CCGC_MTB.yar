
rule Trojan_Win32_Farfli_CCGC_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CCGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 10 01 83 c0 90 01 01 0f 57 c1 66 0f fc c1 0f 11 01 0f 10 41 90 01 01 0f 57 c1 66 0f fc c1 0f 11 41 90 01 01 0f 10 41 90 01 01 0f 57 c1 66 0f fc c1 0f 11 41 90 01 01 0f 10 41 90 01 01 0f 57 c1 66 0f fc c1 0f 11 41 90 01 01 83 c1 90 01 01 3b c7 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}