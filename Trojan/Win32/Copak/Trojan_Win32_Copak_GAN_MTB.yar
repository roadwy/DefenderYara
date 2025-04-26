
rule Trojan_Win32_Copak_GAN_MTB{
	meta:
		description = "Trojan:Win32/Copak.GAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 d6 29 f6 e8 ?? ?? ?? ?? 09 f2 31 39 81 ee ?? ?? ?? ?? 81 ee ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 41 09 d2 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}