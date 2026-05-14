
rule Trojan_Win32_Neoreblamy_NTG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 10 58 6b c0 00 8d 84 05 ?? ?? ff ff 6a 04 } //1
		$a_01_1 = {7d 3f 83 65 c8 00 eb 07 8b 45 c8 40 89 45 c8 81 7d c8 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}