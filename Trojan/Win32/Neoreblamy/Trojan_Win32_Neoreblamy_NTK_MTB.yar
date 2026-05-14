
rule Trojan_Win32_Neoreblamy_NTK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 6b c0 03 8d 84 05 ?? ?? ff ff 6a 04 59 6b c9 00 8b 04 08 48 } //1
		$a_01_1 = {7d 39 83 65 dc 00 eb 07 8b 45 dc 40 89 45 dc 81 7d dc } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}