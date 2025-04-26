
rule Trojan_Win32_Neoreblamy_BU_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.BU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {59 33 d2 8b c6 f7 f1 ff 34 97 ff 34 b3 e8 ?? ?? ff ff 89 04 b3 46 8b 45 fc 03 45 f8 59 59 3b f0 72 } //4
		$a_01_1 = {55 8b ec 81 ec } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}