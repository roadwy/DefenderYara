
rule Trojan_Win32_BlackMoon_GNN_MTB{
	meta:
		description = "Trojan:Win32/BlackMoon.GNN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 0c 89 03 8b 4d f4 8b 55 0c 8b 12 83 c2 08 33 c0 33 db 51 0f b6 c8 fe c1 52 8a 34 39 02 de 8a 14 3b 88 14 39 88 34 3b 02 d6 0f b6 d2 8a 14 3a 8a 0c 30 32 ca 5a 88 0c 10 40 59 e2 d6 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}