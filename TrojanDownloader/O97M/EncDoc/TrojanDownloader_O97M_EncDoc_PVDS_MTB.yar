
rule TrojanDownloader_O97M_EncDoc_PVDS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.PVDS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,1a 00 1a 00 1a 00 00 01 00 "
		
	strings :
		$a_01_0 = {36 39 34 35 55 6f 57 46 49 41 4b 6b 63 39 61 32 62 69 53 53 7a 63 71 33 6e 47 34 } //01 00  6945UoWFIAKkc9a2biSSzcq3nG4
		$a_01_1 = {73 74 58 48 30 66 53 67 4b 69 39 59 50 47 49 61 65 74 76 33 4f 68 5a 78 70 76 6b } //01 00  stXH0fSgKi9YPGIaetv3OhZxpvk
		$a_01_2 = {30 64 53 42 52 4e 75 6e } //01 00  0dSBRNun
		$a_01_3 = {57 76 33 4c 46 4b 63 50 53 63 4b 44 4d 71 42 4c 49 32 4f 70 } //01 00  Wv3LFKcPScKDMqBLI2Op
		$a_01_4 = {4b 55 6b 63 4e 35 54 43 33 68 72 4b 65 63 77 70 6d } //01 00  KUkcN5TC3hrKecwpm
		$a_01_5 = {68 70 73 77 53 48 55 65 } //01 00  hpswSHUe
		$a_01_6 = {73 59 53 62 47 33 5a 30 46 64 43 4b 5a 39 4c 31 5a 58 76 76 41 6a } //01 00  sYSbG3Z0FdCKZ9L1ZXvvAj
		$a_01_7 = {74 35 56 6a 6c 4d } //01 00  t5VjlM
		$a_01_8 = {67 33 33 4d 50 39 66 66 42 6c 76 6f 53 4b 59 30 75 66 4d 6a 65 32 57 35 56 6a } //01 00  g33MP9ffBlvoSKY0ufMje2W5Vj
		$a_01_9 = {65 49 6f 59 47 67 52 4e 64 4d 6b 7a 36 62 64 70 7a 79 6c 47 64 7a } //01 00  eIoYGgRNdMkz6bdpzylGdz
		$a_01_10 = {4c 75 4a 31 58 42 72 6f 67 38 32 70 64 57 32 6d 66 4f 58 45 72 4c 59 36 6a 75 } //01 00  LuJ1XBrog82pdW2mfOXErLY6ju
		$a_01_11 = {47 7a 43 68 54 50 47 6f } //01 00  GzChTPGo
		$a_01_12 = {38 35 4f 50 4a 50 66 7a 71 6d 39 50 38 47 79 4d 54 58 74 59 48 } //01 00  85OPJPfzqm9P8GyMTXtYH
		$a_01_13 = {30 56 4f 52 6e 35 } //01 00  0VORn5
		$a_01_14 = {33 6c 39 6f 6c 6a 79 5a 38 59 50 46 48 6a 33 65 76 } //01 00  3l9oljyZ8YPFHj3ev
		$a_01_15 = {37 54 77 30 41 7a 4f 37 66 } //01 00  7Tw0AzO7f
		$a_01_16 = {73 68 38 69 30 39 66 55 6e 4e 72 39 57 71 4a 72 31 79 44 52 } //01 00  sh8i09fUnNr9WqJr1yDR
		$a_01_17 = {6d 79 50 65 6a 52 38 32 36 32 77 75 } //01 00  myPejR8262wu
		$a_01_18 = {73 46 31 52 62 59 59 52 } //01 00  sF1RbYYR
		$a_01_19 = {6a 77 37 6f 77 78 6b 6e 6e 53 4b } //01 00  jw7owxknnSK
		$a_01_20 = {42 4b 6f 34 34 52 63 39 72 42 6f 5a 76 62 38 51 51 31 32 51 63 5a 77 73 31 33 } //01 00  BKo44Rc9rBoZvb8QQ12QcZws13
		$a_01_21 = {6c 72 77 72 54 4e } //01 00  lrwrTN
		$a_01_22 = {6d 72 75 6a 45 4d 37 41 39 61 72 51 35 57 4b 4e 7a 67 54 } //01 00  mrujEM7A9arQ5WKNzgT
		$a_01_23 = {78 76 43 72 6d 59 36 44 42 70 75 4d 30 72 61 78 45 71 59 4d 45 34 31 } //01 00  xvCrmY6DBpuM0raxEqYME41
		$a_01_24 = {52 43 72 66 79 64 72 58 } //01 00  RCrfydrX
		$a_01_25 = {33 50 59 67 62 6b 30 48 4b 49 49 36 55 4f 4e 72 6a 64 } //00 00  3PYgbk0HKII6UONrjd
	condition:
		any of ($a_*)
 
}