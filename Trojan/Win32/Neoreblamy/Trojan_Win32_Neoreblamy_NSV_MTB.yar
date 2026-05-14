
rule Trojan_Win32_Neoreblamy_NSV_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 45 83 65 dc 00 eb 07 8b 45 dc 40 89 45 dc 81 7d dc } //1
		$a_03_1 = {6a 04 58 c1 e0 02 8b 84 05 ?? ?? ff ff 48 6a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}