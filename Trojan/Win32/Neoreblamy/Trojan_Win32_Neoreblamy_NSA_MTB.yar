
rule Trojan_Win32_Neoreblamy_NSA_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {58 6b c0 00 8b 44 05 ac 03 85 ?? ?? ff ff 6a 04 } //1
		$a_03_1 = {eb 0d 8b 45 f0 89 9c 85 ?? ff ff ff ff 45 f0 83 7d f0 02 } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}