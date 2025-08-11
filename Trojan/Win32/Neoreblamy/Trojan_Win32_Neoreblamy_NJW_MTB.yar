
rule Trojan_Win32_Neoreblamy_NJW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 f4 40 89 45 f4 83 7d f4 02 7d 0d 8b 45 f4 } //2
		$a_03_1 = {8b 45 ec 8b 4d e8 83 c0 ff 89 45 ec 83 d1 ff 89 4d e8 e9 ?? ff ff ff 8b 45 ec 8b 4d e8 83 c0 ff 89 45 ec 83 d1 ff 89 4d e8 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}