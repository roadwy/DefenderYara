
rule Virus_Win32_Chir_gen_dam{
	meta:
		description = "Virus:Win32/Chir.gen!dam,SIGNATURE_TYPE_PEHSTR,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 2e 77 61 62 74 21 3d 2e 61 64 63 74 25 3d 72 2e 64 62 74 1e 3d 2e 64 6f 63 74 17 3d 2e 78 6c 73 74 10 } //01 00 
		$a_01_1 = {83 c0 20 3b f8 77 e2 80 f9 40 74 45 80 f9 2e 74 3c 80 f9 30 72 0f 80 f9 39 72 38 80 f9 41 72 05 80 f9 7e 72 2e } //01 00 
		$a_01_2 = {3d 2e 65 78 65 74 53 3d 2e 73 63 72 74 4c 3d 2e 68 74 6d 74 0b 3d 68 74 6d 6c 74 04 } //01 00  ⸽硥瑥㵓献牣䱴⸽瑨瑭㴋瑨汭Ѵ
		$a_01_3 = {ff 96 80 00 00 00 58 03 c7 c7 00 2e 65 6d 6c c7 40 04 00 00 00 00 6a 00 57 ff 56 70 83 f8 ff } //01 00 
		$a_01_4 = {3c 68 74 6d 6c 3e 3c 48 45 41 44 3e 3c 2f 48 45 41 44 3e 3c 62 6f 64 79 20 62 67 43 6f 6c 6f 72 3d 33 44 23 66 66 66 66 66 66 3e 3c 69 66 72 61 6d 65 20 73 72 63 3d 33 44 63 69 64 3a } //00 00  <html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:
	condition:
		any of ($a_*)
 
}