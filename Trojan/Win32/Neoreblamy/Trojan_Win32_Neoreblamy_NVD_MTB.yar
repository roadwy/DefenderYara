
rule Trojan_Win32_Neoreblamy_NVD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NVD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 4d b0 83 c1 01 89 4d b0 83 7d b0 01 7d 10 8b 55 b0 } //1
		$a_03_1 = {6b c2 00 8b 8c 05 ?? ?? ff ff 83 c1 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}