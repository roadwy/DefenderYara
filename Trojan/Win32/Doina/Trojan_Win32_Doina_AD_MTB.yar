
rule Trojan_Win32_Doina_AD_MTB{
	meta:
		description = "Trojan:Win32/Doina.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 44 79 08 8b d0 c7 45 fc 00 30 00 00 81 e2 00 f0 00 00 66 3b 55 fc 74 ?? c7 45 fc 00 a0 00 00 66 3b 55 fc 75 ?? 25 ff 0f 00 00 03 01 01 34 18 47 3b 7d f8 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}