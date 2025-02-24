
rule Trojan_Win32_Neoreblamy_NFC_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NFC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 04 59 c1 e1 00 8b 8c 0d ?? ?? ff ff 6a 04 5a c1 e2 00 8b 94 15 ?? ?? ff ff 4a 6a 04 5e c1 e6 00 } //2
		$a_01_1 = {eb 07 8b 45 ac 40 89 45 ac 83 7d ac 03 7d 10 8b 45 ac } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}