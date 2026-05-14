
rule Trojan_Win32_Neoreblamy_NTQ_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {58 6b c0 05 8d 84 05 ?? ?? ff ff 6a 04 59 } //1
		$a_01_1 = {7e 22 83 65 8c 00 eb 07 8b 45 8c 40 89 45 8c 81 7d 8c } //2
		$a_01_2 = {1b c9 41 81 f9 81 4d 05 e1 1b c0 33 c9 40 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=4
 
}