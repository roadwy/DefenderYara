
rule Trojan_Win32_Fareit_AKN_MTB{
	meta:
		description = "Trojan:Win32/Fareit.AKN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 00 5e 96 f7 f0 8b c6 5e 5b c3 90 0a 3f 00 6a 00 6a 00 } //1
		$a_03_1 = {32 45 fb 88 06 8a 06 32 45 f9 88 06 eb [0-04] 8a 45 fa 88 06 47 43 49 75 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}