
rule Backdoor_Win32_Bazarldr_AD_MTB{
	meta:
		description = "Backdoor:Win32/Bazarldr.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {be 08 0f b6 55 90 01 01 33 ca a1 90 01 04 03 45 90 01 01 88 08 e9 90 09 13 00 41 8a 89 90 01 04 88 4d 90 01 01 a1 90 01 04 03 45 90 01 01 0f 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}