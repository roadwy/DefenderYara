
rule Trojan_Win32_Fauppod_GAN_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {40 48 8d 05 90 01 04 31 38 42 8d 05 90 01 04 31 30 42 89 d0 89 e8 50 8f 05 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}