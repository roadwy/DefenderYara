
rule Trojan_Win32_Lazy_GAN_MTB{
	meta:
		description = "Trojan:Win32/Lazy.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c2 01 35 90 01 04 83 c0 90 01 01 8d 05 90 01 04 89 38 01 c2 83 f0 90 01 01 01 2d 90 01 04 b8 90 01 04 01 1d 90 01 04 b9 02 00 00 00 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}