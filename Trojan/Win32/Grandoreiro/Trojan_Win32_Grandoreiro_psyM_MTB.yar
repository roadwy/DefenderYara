
rule Trojan_Win32_Grandoreiro_psyM_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 55 68 ab 89 45 00 64 ff 30 64 89 20 8b 45 fc e8 9b fd ff ff 33 c0 5a 59 59 64 89 10 eb 15 e9 2c bf fa ff 8b 55 fc 8b 45 fc e8 a9 00 00 00 e8 2c c3 fa ff 8b 45 fc 80 b8 a4 00 00 00 00 74 bf } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}