
rule Trojan_Win32_Mikey_ARA_MTB{
	meta:
		description = "Trojan:Win32/Mikey.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 54 24 0c 69 d2 d2 f8 62 7e 89 54 24 0c 8a 10 30 11 41 40 3b cf 75 e8 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}