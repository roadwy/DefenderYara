
rule Trojan_Win32_Neoreblamy_NSB_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 c4 40 89 45 c4 83 7d c4 02 7d 0d 8b 45 c4 } //1
		$a_03_1 = {6b d2 00 8d 94 15 ?? ?? ff ff 89 04 0a } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}