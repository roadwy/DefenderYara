
rule Trojan_Win32_Neoreblamy_NMV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 bc 40 89 45 bc 83 7d bc 02 7d 10 8b 45 bc } //1
		$a_03_1 = {eb 07 83 a5 ?? ?? ff ff 00 6a 04 58 c1 e0 00 83 bc 05 ?? ?? ff ff 00 74 1c 6a 04 58 6b c0 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}