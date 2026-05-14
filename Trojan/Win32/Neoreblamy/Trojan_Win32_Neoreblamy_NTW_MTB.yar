
rule Trojan_Win32_Neoreblamy_NTW_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NTW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 fc 40 89 45 fc 83 7d fc 02 7d 0d 8b 45 fc } //2
		$a_03_1 = {58 6b c0 00 8b 44 05 ac 89 85 ?? ?? ff ff 6a 04 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1) >=3
 
}