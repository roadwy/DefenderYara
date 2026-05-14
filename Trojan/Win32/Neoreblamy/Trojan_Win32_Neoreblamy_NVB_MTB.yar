
rule Trojan_Win32_Neoreblamy_NVB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 55 d4 83 c2 01 89 55 d4 83 7d d4 01 7d 0d 8b 45 d4 } //1
		$a_03_1 = {6b c2 00 8b 8c 05 ?? ?? ff ff 83 e9 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}