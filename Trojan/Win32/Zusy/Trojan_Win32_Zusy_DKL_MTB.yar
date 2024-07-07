
rule Trojan_Win32_Zusy_DKL_MTB{
	meta:
		description = "Trojan:Win32/Zusy.DKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 b8 d1 e0 8b 55 bc 8d 04 10 0f b7 00 c1 e0 02 8b 55 c0 8d 04 10 8b 55 f4 8b 00 89 02 80 7d b0 00 75 02 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}