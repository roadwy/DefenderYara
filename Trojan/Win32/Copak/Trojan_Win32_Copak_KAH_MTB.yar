
rule Trojan_Win32_Copak_KAH_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8b 17 81 e9 90 01 04 4e 21 de 81 e2 90 01 04 41 89 f3 21 ce 31 10 21 c9 01 db 40 01 f3 29 de 09 de 47 01 f6 29 f3 29 d9 81 f8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}