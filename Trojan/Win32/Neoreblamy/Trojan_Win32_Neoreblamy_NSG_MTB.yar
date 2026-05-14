
rule Trojan_Win32_Neoreblamy_NSG_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NSG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7e 27 83 65 ec 00 eb 07 8b 45 ec 40 89 45 ec } //1
		$a_03_1 = {58 6b c0 00 8d 84 05 ?? ?? ff ff 6a 04 59 6b c9 03 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*2) >=3
 
}