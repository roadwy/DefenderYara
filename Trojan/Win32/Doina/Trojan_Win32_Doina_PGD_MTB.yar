
rule Trojan_Win32_Doina_PGD_MTB{
	meta:
		description = "Trojan:Win32/Doina.PGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {66 0f be 06 8b 4d e4 0f b7 d0 3b 4d e8 ?? ?? 83 7d e8 ?? 8d 41 01 89 45 e4 8d 45 d4 0f 43 45 d4 66 89 14 48 33 d2 66 89 54 48 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}