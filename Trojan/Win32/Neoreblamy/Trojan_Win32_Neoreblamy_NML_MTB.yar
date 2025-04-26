
rule Trojan_Win32_Neoreblamy_NML_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NML!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {eb 0d 8b 85 ?? ?? ff ff 40 89 } //1
		$a_03_1 = {8b 00 40 8b 8d ?? ?? ff ff 89 01 8b 85 ?? ?? ff ff 40 50 8d 8d } //2
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}