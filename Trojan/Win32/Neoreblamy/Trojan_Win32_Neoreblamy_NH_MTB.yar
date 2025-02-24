
rule Trojan_Win32_Neoreblamy_NH_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 a0 48 89 45 a0 83 7d a0 00 7c 38 8b 45 } //2
		$a_01_1 = {55 8b ec 8b 45 0c 53 56 8b 75 08 33 db 2b c6 83 c0 03 c1 e8 02 39 75 0c 57 1b ff f7 d7 23 f8 76 10 } //1
		$a_01_2 = {8b 45 e4 40 89 45 e4 83 7d e4 04 7d 10 8b 45 e4 c7 84 85 b0 fc ff ff } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}