
rule Trojan_Win32_Neoreblamy_NJM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 9c 40 89 45 9c 83 7d 9c 02 } //1
		$a_01_1 = {6a 04 58 6b c0 00 83 bc 05 d8 fe ff ff 00 74 1c 6a 04 58 6b c0 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}