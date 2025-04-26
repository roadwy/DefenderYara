
rule Trojan_Win32_Tilcun_gen_A{
	meta:
		description = "Trojan:Win32/Tilcun.gen!A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b7 45 fa c1 e8 08 8b 55 ec 32 02 8b 55 e8 88 02 8b 45 ec 0f b6 00 66 03 45 fa 66 69 c0 2e 16 66 05 38 15 66 89 45 fa 8b 45 e8 40 89 45 e8 8b 45 ec 40 89 45 ec ff 45 f0 ff 4d e4 75 c2 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}