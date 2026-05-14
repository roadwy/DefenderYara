
rule Trojan_Win64_EggStremeLoader_N_dha{
	meta:
		description = "Trojan:Win64/EggStremeLoader.N!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_42_0 = {48 b9 00 00 66 89 8c 24 90 01 01 00 00 00 90 02 10 b9 48 ba 00 00 90 02 16 b8 41 b8 00 00 90 02 16 b8 49 b9 00 00 90 00 01 } //1
		$a_66_1 = {84 24 90 01 01 00 00 00 48 ba 90 02 10 66 c7 84 24 90 01 01 00 00 00 41 b8 90 02 10 c7 84 24 90 01 01 00 00 00 6b 0c ad 4a 66 90 02 10 c7 84 24 90 01 01 00 00 00 49 b9 90 00 01 00 1d 40 41 8a 00 34 } //15360
		$a_04_2 = {0f b6 c8 6b c2 0d 83 c0 1d 41 23 c3 7d 07 ff c8 41 0b c2 ff c0 00 00 5d 04 00 00 a7 54 07 80 5c 2e 00 00 a8 54 07 80 00 00 01 00 1e 00 18 00 45 78 70 6c 6f 69 74 3a 50 79 74 68 6f 6e 2f 58 53 53 50 6c 64 2e 42 42 00 00 01 40 05 82 59 00 04 00 e7 68 00 00 00 00 64 00 c7 05 67 0f ec f2 e6 a7 3f 99 ec 1e bc 3e ad bc e6 99 ac d0 e3 31 31 80 d1 d1 0f ac e4 80 3f fe 14 14 8f c7 05 67 0f ec f2 e6 a7 3f 99 ec 1e bc 3e c7 ac da 0b 31 80 e3 da 13 f2 1e c7 ac da 0b 31 80 fe 14 05 8f c7 05 67 0f ec f2 e6 a7 3f 99 ec 1e bc 3e e3 1e 1e 0b f2 99 67 bc a7 ea ac bc 13 fe 14 d7 5d 04 00 00 a8 54 07 80 5c 2c 00 } //-16299
	condition:
		((#a_42_0  & 1)*1+(#a_66_1  & 1)*15360+(#a_04_2  & 1)*-16299) >=1
 
}