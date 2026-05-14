
rule Trojan_Win32_Neoreblamy_NUD_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {eb 07 8b 45 e8 48 89 45 e8 83 7d e8 e8 } //2
		$a_01_1 = {07 8b 45 ec 40 89 45 ec 83 7d ec 01 7d 0d 8b 45 ec } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}