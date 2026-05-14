
rule Trojan_Win32_Neoreblamy_NRK_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 6d 83 65 d8 00 eb 07 8b 45 d8 40 89 45 d8 } //1
		$a_01_1 = {03 4d 80 8b 45 e4 99 f7 bd 78 ff ff ff 33 ca 8b c1 99 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}