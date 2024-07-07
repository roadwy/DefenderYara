
rule Trojan_Win32_Rozena_GPD_MTB{
	meta:
		description = "Trojan:Win32/Rozena.GPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc c1 e0 05 33 45 fc 89 c2 8b 4d 08 8b 45 f8 01 c8 0f b6 00 0f b6 c0 31 d0 89 45 fc 83 45 f8 01 8b 45 f8 3b 45 0c 72 d6 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}