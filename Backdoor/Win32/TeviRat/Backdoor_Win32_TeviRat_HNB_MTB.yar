
rule Backdoor_Win32_TeviRat_HNB_MTB{
	meta:
		description = "Backdoor:Win32/TeviRat.HNB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 44 0d d4 8b 55 08 32 c2 32 04 3a 41 83 f9 10 88 04 3a 75 02 33 c9 ff 45 08 39 75 08 72 e1 } //1
		$a_01_1 = {03 01 8b 55 08 03 c2 8b 55 f8 01 10 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}