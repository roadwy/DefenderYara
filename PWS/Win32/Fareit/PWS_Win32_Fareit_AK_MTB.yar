
rule PWS_Win32_Fareit_AK_MTB{
	meta:
		description = "PWS:Win32/Fareit.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 34 24 0f 90 0a 40 00 ff 37 90 02 ff 59 90 02 ff 90 03 01 01 89 09 0c 18 90 02 ff 83 90 03 01 01 c2 d2 04 90 02 ff 83 90 03 01 01 d7 c7 04 90 00 } //1
		$a_03_1 = {31 34 24 66 90 0a 40 00 ff 37 90 02 ff 59 90 02 ff 90 03 01 01 89 09 0c 18 90 02 ff 83 90 03 01 01 c2 d2 04 90 02 ff 83 90 03 01 01 d7 c7 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}