
rule Trojan_Win32_Neoreblamy_NLA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {eb 15 6a 04 58 6b c0 00 8b 44 05 cc 48 6a 04 59 6b c9 00 89 44 0d cc 6a 04 58 6b c0 00 } //2
		$a_01_1 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 02 7d 0d 8b 45 fc } //1
		$a_01_2 = {33 ff 33 db 8b c3 8d 4c 24 20 33 c7 0b c6 99 52 50 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}