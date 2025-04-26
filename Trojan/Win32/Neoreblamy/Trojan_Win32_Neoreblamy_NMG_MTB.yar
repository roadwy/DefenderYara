
rule Trojan_Win32_Neoreblamy_NMG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 9c 40 89 45 9c 83 7d 9c 03 7d 10 8b 45 9c } //1
		$a_03_1 = {eb 04 83 4d fc ff 6a 04 58 6b c0 00 8b 84 05 ?? ?? ff ff 48 6a 04 59 6b c9 00 } //2
		$a_01_2 = {eb 07 8b 45 94 40 89 45 94 83 7d 94 01 7d 10 8b 45 94 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}