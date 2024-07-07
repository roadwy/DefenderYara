
rule PWS_Win32_Fareit_VD_MTB{
	meta:
		description = "PWS:Win32/Fareit.VD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {47 43 4e 75 90 09 0b 00 8b cf b2 90 02 08 8a 03 90 18 32 c2 88 01 c3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}