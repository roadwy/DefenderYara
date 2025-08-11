
rule Trojan_Win32_Neoreblamy_NMZ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 01 7d 0d 8b 45 fc } //1
		$a_03_1 = {eb e3 6a 04 58 6b c0 03 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 03 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}