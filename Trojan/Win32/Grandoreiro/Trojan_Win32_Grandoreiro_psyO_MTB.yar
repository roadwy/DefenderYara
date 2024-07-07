
rule Trojan_Win32_Grandoreiro_psyO_MTB{
	meta:
		description = "Trojan:Win32/Grandoreiro.psyO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 55 68 b4 08 4a 00 64 ff 30 64 89 20 8b 45 fc e8 c6 fc ff ff 33 c0 5a 59 59 64 89 10 eb 15 e9 63 54 f6 ff 8b 55 fc 8b 45 fc e8 d0 00 00 00 e8 ab 58 f6 ff 8b 45 fc 80 b8 a4 00 00 00 00 74 bf } //7
	condition:
		((#a_01_0  & 1)*7) >=7
 
}