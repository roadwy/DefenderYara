
rule Trojan_Win32_Sabsik_POIU_MTB{
	meta:
		description = "Trojan:Win32/Sabsik.POIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 13 e6 95 35 a1 08 aa 55 ba b2 5c 62 da b1 9e 9d da b1 d6 9d dd c1 e5 0e 12 de 95 25 89 09 82 55 aa aa 5d 7a da } //00 00 
	condition:
		any of ($a_*)
 
}