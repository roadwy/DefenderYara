
rule Trojan_Win32_Khalesi_GAN_MTB{
	meta:
		description = "Trojan:Win32/Khalesi.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 d3 31 39 89 d2 21 d3 81 c1 01 00 00 00 39 f1 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}