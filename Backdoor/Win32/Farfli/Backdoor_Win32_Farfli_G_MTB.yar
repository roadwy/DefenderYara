
rule Backdoor_Win32_Farfli_G_MTB{
	meta:
		description = "Backdoor:Win32/Farfli.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {80 ea 7a 80 f2 19 88 91 90 01 04 50 33 c0 74 90 09 06 00 8a 91 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}