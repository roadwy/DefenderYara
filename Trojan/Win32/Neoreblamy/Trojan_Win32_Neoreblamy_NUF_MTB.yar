
rule Trojan_Win32_Neoreblamy_NUF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 55 8c 83 c2 01 89 55 8c 83 7d 8c 01 7d 10 8b 45 8c } //1
		$a_03_1 = {ba 04 00 00 00 6b c2 00 83 bc 05 ?? ?? ff ff 00 75 } //2
		$a_01_2 = {eb 09 8b 4d b0 83 c1 01 89 4d b0 83 7d b0 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}