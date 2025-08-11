
rule Trojan_Win32_Neoreblamy_NJA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 ec 40 89 45 ec 83 7d ec ?? 7d 10 8b 45 ec } //1
		$a_03_1 = {6a 04 58 6b c0 00 8b 84 05 ?? ff ff ff 3b 85 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}