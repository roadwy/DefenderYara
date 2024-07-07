
rule Backdoor_Win32_Bifrose_ABF_MTB{
	meta:
		description = "Backdoor:Win32/Bifrose.ABF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e0 33 d2 52 50 8b c3 c1 e0 03 8d 04 80 99 03 04 24 13 54 24 04 83 c4 08 8b 55 fc 03 d0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}