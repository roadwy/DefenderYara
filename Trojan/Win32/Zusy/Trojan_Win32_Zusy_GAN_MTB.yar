
rule Trojan_Win32_Zusy_GAN_MTB{
	meta:
		description = "Trojan:Win32/Zusy.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {4e 09 c2 c3 31 06 81 c6 04 00 00 00 29 d2 39 de } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}