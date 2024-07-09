
rule PWS_Win32_Fareit_AA_MTB{
	meta:
		description = "PWS:Win32/Fareit.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 c1 04 eb 90 0a ff 02 (14 14 14 14 14|00 00 00 00 00) 90 0a ff 02 8f 04 08 90 0a ff 02 81 34 24 90 0a ff 02 ff 34 08 } //1
		$a_03_1 = {14 83 c1 04 90 0a ff 02 (14 14 14 14 14|00 00 00 00 00) 90 0a ff 02 8f 04 08 90 0a ff 02 81 34 24 90 0a ff 02 ff 34 08 } //1
		$a_03_2 = {83 c1 04 14 90 0a ff 02 (14 14 14 14 14|00 00 00 00 00) 90 0a ff 02 8f 04 08 90 0a ff 02 81 34 24 90 0a ff 02 ff 34 08 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=1
 
}