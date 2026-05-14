
rule Trojan_Win32_Neoreblamy_NSM_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {59 6b c9 00 8d 8c 0d 14 ff ff ff 6a 04 } //1
		$a_01_1 = {eb 07 8b 45 d4 40 89 45 d4 83 7d d4 01 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}