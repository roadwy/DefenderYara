
rule Trojan_Win32_Neoreblamy_NTM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 c1 e0 00 8d 84 05 ?? ?? ff ff 6a 04 59 } //1
		$a_01_1 = {eb 07 8b 45 b0 40 89 45 b0 83 7d b0 02 7d 10 8b 45 b0 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}