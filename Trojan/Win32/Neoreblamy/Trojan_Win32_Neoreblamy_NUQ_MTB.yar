
rule Trojan_Win32_Neoreblamy_NUQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 4d b4 83 c1 01 89 4d b4 83 7d b4 01 7d 10 8b 55 b4 } //1
		$a_03_1 = {6b c8 00 8b 95 ?? ?? ff ff 89 54 0d } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}