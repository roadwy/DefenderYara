
rule Trojan_Win32_Rozena_SPA_MTB{
	meta:
		description = "Trojan:Win32/Rozena.SPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8d 95 79 fe ff ff 8b 45 e4 01 d0 0f b6 08 8b 45 e4 99 f7 7d e0 89 d0 0f b6 84 05 71 fe ff ff 31 c1 89 ca 8d 8d 79 fe ff ff 8b 45 e4 01 c8 88 10 83 45 e4 01 8b 45 e4 3d 62 01 00 00 76 c2 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}