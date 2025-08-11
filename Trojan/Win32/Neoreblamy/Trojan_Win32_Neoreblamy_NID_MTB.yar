
rule Trojan_Win32_Neoreblamy_NID_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NID!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 c4 40 89 45 c4 83 7d c4 ?? 7d 10 8b 45 c4 } //1
		$a_03_1 = {eb 07 83 a5 ?? ?? ff ff 00 6a 04 58 d1 e0 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}