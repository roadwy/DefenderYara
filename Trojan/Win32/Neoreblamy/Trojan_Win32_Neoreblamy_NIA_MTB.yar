
rule Trojan_Win32_Neoreblamy_NIA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 07 8b 45 a4 40 89 45 a4 83 7d a4 ?? 7d 10 8b 45 a4 } //1
		$a_03_1 = {6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}