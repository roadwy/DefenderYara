
rule Trojan_Win32_Neoreblamy_NIF_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NIF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e4 40 89 45 e4 83 7d e4 03 7d 10 8b 45 e4 } //1
		$a_01_1 = {6a 04 58 6b c0 00 83 bc 05 40 ff ff ff 00 74 0c } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}