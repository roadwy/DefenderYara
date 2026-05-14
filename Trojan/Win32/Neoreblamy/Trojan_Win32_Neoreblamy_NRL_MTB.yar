
rule Trojan_Win32_Neoreblamy_NRL_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.NRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {7d 1b 8b 45 f8 8b 00 33 45 fc 99 89 45 f0 89 55 f4 8d 45 f0 } //1
		$a_01_1 = {eb 07 8b 45 fc 40 89 45 fc 81 7d fc } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}