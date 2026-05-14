
rule Trojan_Win32_Neoreblamy_NSH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 2e 83 65 dc 00 eb 07 8b 45 dc 40 89 45 dc 81 7d dc } //1
		$a_03_1 = {d1 e0 8d 84 05 ?? ?? ff ff 6a 04 59 6b c9 03 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}