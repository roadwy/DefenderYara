
rule Trojan_Win32_Neoreblamy_NTS_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 b0 40 89 45 b0 83 7d b0 01 7d 10 8b 45 b0 } //2
		$a_01_1 = {6b c0 00 8b 44 05 e8 48 6a 04 59 6b c9 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}