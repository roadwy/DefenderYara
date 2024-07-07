
rule Trojan_Win32_Stealerc_GAA_MTB{
	meta:
		description = "Trojan:Win32/Stealerc.GAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 69 f6 90 01 04 69 0c b8 90 01 04 47 8b c1 c1 e8 18 33 c1 69 c8 90 01 04 8b 44 24 2c 33 f1 3b f8 7c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}