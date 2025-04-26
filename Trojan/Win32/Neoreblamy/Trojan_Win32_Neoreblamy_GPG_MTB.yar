
rule Trojan_Win32_Neoreblamy_GPG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 05 6a 07 59 cd 29 6a 01 68 15 00 00 40 6a 03 e8 cb 31 00 00 83 c4 0c 6a 03 e8 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}
rule Trojan_Win32_Neoreblamy_GPG_MTB_2{
	meta:
		description = "Trojan:Win32/Neoreblamy.GPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 48 8b 4d e0 03 4d f4 88 41 01 0f b6 45 ff 03 45 f4 89 45 f4 eb 92 } //3
		$a_01_1 = {99 6a 0f 59 f7 f9 83 c2 0a 88 55 ff 0f b6 45 ff 03 45 f4 3b 45 ec 72 0b } //1
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}