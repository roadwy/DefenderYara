
rule Trojan_Win32_Neoreblamy_NUP_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 09 8b 45 9c 83 c0 01 89 45 9c 83 7d 9c 01 7d 10 8b 4d 9c } //1
		$a_01_1 = {88 07 8a 46 01 88 47 01 8a 46 02 c1 e9 02 88 47 02 83 c6 03 83 c7 03 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}