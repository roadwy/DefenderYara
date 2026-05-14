
rule Trojan_Win32_Neoreblamy_NSC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 98 40 89 45 98 83 7d 98 02 7d 16 } //1
		$a_03_1 = {c1 e1 00 8b 04 08 89 85 ?? ?? ff ff 6a 08 58 6b c0 00 8d 84 05 ?? ff ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}