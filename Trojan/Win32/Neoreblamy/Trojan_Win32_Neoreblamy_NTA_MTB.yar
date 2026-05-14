
rule Trojan_Win32_Neoreblamy_NTA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 d8 40 89 45 d8 83 7d d8 03 7d 10 8b 45 d8 } //1
		$a_03_1 = {d1 e1 8b 04 08 89 85 ?? ?? ff ff 6a 0c 58 6b c0 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}