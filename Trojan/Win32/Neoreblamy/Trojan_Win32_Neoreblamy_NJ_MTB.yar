
rule Trojan_Win32_Neoreblamy_NJ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 d8 48 89 45 d8 83 7d d8 00 7c 11 8b 45 d8 } //1
		$a_01_1 = {eb 07 8b 45 c8 40 89 45 c8 83 7d c8 04 7d 10 8b 45 c8 } //2
		$a_01_2 = {eb 07 8b 45 c0 40 89 45 c0 83 7d c0 02 7d 0d 8b 45 c0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}