
rule Trojan_Win32_Fragtor_BSA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 95 2c ff ff ff 8b c1 2b d1 81 fa 00 10 00 00 72 14 8b 49 fc 83 c2 23 2b c1 83 c0 fc 83 f8 1f 0f 87 d8 06 00 00 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}