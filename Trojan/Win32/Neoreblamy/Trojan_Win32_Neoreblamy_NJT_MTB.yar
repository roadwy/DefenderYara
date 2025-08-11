
rule Trojan_Win32_Neoreblamy_NJT_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 8b 45 f4 40 89 45 f4 83 7d f4 01 7d 0d 8b 45 f4 } //1
		$a_01_1 = {eb 07 8b 45 f8 48 89 45 f8 83 7d f8 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}