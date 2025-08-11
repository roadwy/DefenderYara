
rule Trojan_Win32_Neoreblamy_NJG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 88 40 89 45 88 83 7d 88 02 7d 10 8b 45 88 } //1
		$a_03_1 = {6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 89 85 ?? ?? ff ff 6a 04 58 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}