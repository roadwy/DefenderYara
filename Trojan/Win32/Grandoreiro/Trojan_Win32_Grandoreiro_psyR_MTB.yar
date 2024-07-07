
rule Trojan_Win32_Grandoreiro_psyR_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 8b ec 51 53 56 57 89 4d fc 8b da 8b f0 8b c3 ff 50 f4 8b d8 8b 45 fc 89 18 33 c0 55 68 4a 88 45 00 64 ff 30 64 89 20 8b ce 83 ca ff 8b c3 8b 38 ff 57 2c 33 c0 5a 59 59 64 89 10 eb 16 e9 8d c0 fa ff } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}