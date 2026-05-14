
rule Trojan_Win32_Neoreblamy_NTD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {7d 46 83 65 90 00 eb 07 8b 45 90 40 89 45 90 81 7d 90 } //1
		$a_01_1 = {d3 f8 8b 4d fc 2b 4d f8 33 c1 99 } //1
		$a_03_2 = {58 6b c0 03 8d 84 05 ?? ?? ff ff 6a 04 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}