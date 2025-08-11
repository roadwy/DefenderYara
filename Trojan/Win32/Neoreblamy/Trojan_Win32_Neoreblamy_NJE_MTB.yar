
rule Trojan_Win32_Neoreblamy_NJE_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NJE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 f8 40 89 45 f8 83 7d f8 02 7d 0d 8b 45 f8 } //1
		$a_01_1 = {07 8b 45 fc 40 89 45 fc 83 7d fc 04 7d 0d 8b 45 fc } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}