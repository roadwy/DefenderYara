
rule Trojan_Win32_AveMariaRat_MS_MTB{
	meta:
		description = "Trojan:Win32/AveMariaRat.MS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_00_0 = {f0 14 78 38 f7 be 70 16 37 b8 3e 75 b0 f0 41 cc 1a 71 10 32 7b fb b9 60 15 3d 6e bf 43 10 34 62 dc 30 b1 fb 4c 3e 75 7e bb 37 3d 80 36 39 82 c1 1f f5 41 d6 bd f7 6f 69 4f 32 bb f8 cf f7 47 3b 07 f5 74 f1 b8 7e 12 31 bf 6d 10 3d bb 37 bc 37 72 7a b6 f4 44 cf b3 70 13 30 fb f9 fb fa f9 fe 05 30 27 38 31 4a 3c c1 ec 35 f0 bb f4 36 b0 38 } //01 00 
		$a_03_1 = {a1 88 58 41 00 89 45 d8 8b 0d 90 01 04 89 4d dc 8b 15 90 01 04 89 55 e0 66 a1 90 01 04 66 89 45 e4 8a 0d 90 01 04 88 4d e6 68 90 01 04 68 90 01 04 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}