
rule Trojan_Win32_Windigo_DSK_MTB{
	meta:
		description = "Trojan:Win32/Windigo.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f4 8b 08 03 ca 8a 51 03 8a da 8a c2 80 e2 f0 c0 e0 06 0a 41 02 80 e3 fc c0 e2 02 0a 11 c0 e3 04 0a 59 01 8d 4d f8 88 14 3e 88 5c 3e 01 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}