
rule Trojan_Win32_Neoreblamy_NTH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 59 6b c9 00 89 84 0d ?? ?? ff ff 6a 04 } //1
		$a_01_1 = {eb 07 8b 45 a0 40 89 45 a0 83 7d a0 01 7d 0d 8b 45 a0 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}