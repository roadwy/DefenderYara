
rule Trojan_Win32_Neoreblamy_NUU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 55 cc 83 c2 01 89 55 cc 83 7d cc 01 7d 10 8b 45 cc } //1
		$a_03_1 = {6b c8 00 8b 94 0d ?? ?? ff ff 83 c2 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}