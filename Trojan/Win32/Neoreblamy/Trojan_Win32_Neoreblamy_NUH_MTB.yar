
rule Trojan_Win32_Neoreblamy_NUH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 84 40 89 45 84 83 7d 84 01 7d 0d 8b 45 84 } //2
		$a_03_1 = {58 6b c0 00 8b 84 05 ?? ?? ff ff 6a 04 59 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}