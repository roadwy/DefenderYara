
rule SoftwareBundler_Win32_SquareNet{
	meta:
		description = "SoftwareBundler:Win32/SquareNet,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 1f 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 52 65 6c 65 61 73 65 5c 55 70 64 61 74 65 72 53 65 72 76 69 63 65 2e 70 64 62 00 } //03 00 
		$a_01_1 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2f 00 76 00 25 00 64 00 2f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 69 00 6e 00 66 00 6f 00 2e 00 62 00 69 00 6e 00 } //02 00 
		$a_01_2 = {7b 00 39 00 43 00 44 00 38 00 36 00 35 00 43 00 41 00 2d 00 43 00 33 00 31 00 39 00 2d 00 34 00 42 00 46 00 39 00 2d 00 38 00 35 00 37 00 37 00 2d 00 45 00 41 00 36 00 45 00 43 00 37 00 46 00 33 00 36 00 41 00 45 00 37 00 7d 00 00 00 } //01 00 
		$a_01_3 = {4d 00 65 00 64 00 69 00 61 00 44 00 65 00 76 00 53 00 76 00 63 00 00 00 } //01 00 
		$a_01_4 = {57 00 69 00 6e 00 44 00 65 00 76 00 53 00 76 00 63 00 00 00 } //01 00 
		$a_01_5 = {4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 48 00 6f 00 73 00 74 00 53 00 72 00 76 00 } //02 00 
		$a_01_6 = {2f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2f 00 76 00 25 00 64 00 2f 00 70 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 69 00 6e 00 66 00 6f 00 2e 00 62 00 69 00 6e 00 00 00 } //01 00 
		$a_01_7 = {4d 00 65 00 64 00 69 00 61 00 44 00 65 00 76 00 69 00 63 00 65 00 53 00 76 00 63 00 00 00 } //01 00 
		$a_01_8 = {5c 52 65 6c 65 61 73 65 5c 50 72 6f 74 65 63 74 65 64 53 65 72 76 69 63 65 2e 70 64 62 00 } //02 00 
		$a_01_9 = {73 00 74 00 61 00 74 00 65 00 3d 00 6f 00 6b 00 26 00 69 00 64 00 3d 00 25 00 73 00 26 00 6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 63 00 63 00 3d 00 25 00 64 00 26 00 63 00 6c 00 69 00 63 00 6b 00 3d 00 25 00 64 00 00 00 } //02 00 
		$a_01_10 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 73 00 76 00 63 00 2f 00 66 00 62 00 3f 00 00 00 } //01 00 
		$a_01_11 = {5c 75 70 64 61 74 65 72 69 6e 66 6f 00 } //01 00 
		$a_01_12 = {6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 6f 00 73 00 3d 00 25 00 73 00 26 00 73 00 76 00 63 00 76 00 65 00 72 00 3d 00 25 00 73 00 26 00 76 00 65 00 72 00 3d 00 25 00 64 00 } //01 00 
		$a_01_13 = {70 72 6f 74 65 63 74 65 64 53 76 63 49 6e 66 6f 00 } //01 00 
		$a_01_14 = {67 5f 41 55 70 64 61 74 65 72 53 76 63 4e 61 6d 65 00 } //01 00 
		$a_01_15 = {33 c9 39 4c 24 08 76 13 8b 44 24 04 8a 54 24 0c 03 c1 30 10 41 3b 4c 24 08 72 ed } //02 00 
		$a_01_16 = {72 00 65 00 66 00 3d 00 25 00 73 00 26 00 73 00 69 00 74 00 65 00 5f 00 69 00 64 00 3d 00 25 00 73 00 26 00 6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 73 00 74 00 65 00 70 00 3d 00 64 00 62 00 6c 00 63 00 6c 00 69 00 63 00 6b 00 } //02 00 
		$a_01_17 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 5f 00 63 00 68 00 65 00 63 00 6b 00 3f 00 } //02 00 
		$a_01_18 = {5c 00 55 00 70 00 64 00 61 00 74 00 65 00 53 00 65 00 72 00 76 00 5c 00 66 00 62 00 5f 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 00 00 } //02 00 
		$a_01_19 = {26 00 63 00 6c 00 69 00 63 00 6b 00 3d 00 25 00 64 00 00 00 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 00 00 77 00 77 00 77 00 2e 00 00 00 } //03 00 
		$a_01_20 = {22 74 61 73 6b 55 72 69 22 20 3a 20 22 2f 75 70 2f 72 25 64 2f 75 70 2e 62 69 6e } //03 00 
		$a_01_21 = {2d 00 35 00 33 00 37 00 33 00 42 00 34 00 30 00 00 00 } //03 00 
		$a_01_22 = {2d 00 69 00 6b 00 65 00 37 00 30 00 38 00 39 00 62 00 00 00 } //01 00 
		$a_01_23 = {73 00 79 00 73 00 74 00 65 00 6d 00 75 00 70 00 64 00 61 00 74 00 65 00 73 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 70 00 2e 00 61 00 73 00 68 00 78 00 3f 00 61 00 3d 00 } //01 00 
		$a_00_24 = {26 00 73 00 69 00 74 00 65 00 5f 00 69 00 64 00 3d 00 00 00 26 00 63 00 6c 00 69 00 63 00 6b 00 5f 00 69 00 64 00 3d 00 00 00 } //02 00 
		$a_01_25 = {7b 00 38 00 46 00 38 00 34 00 42 00 45 00 44 00 41 00 2d 00 34 00 41 00 39 00 33 00 2d 00 34 00 30 00 34 00 36 00 2d 00 39 00 37 00 44 00 32 00 2d 00 37 00 41 00 42 00 38 00 42 00 31 00 44 00 41 00 34 00 39 00 44 00 38 00 7d 00 } //02 00 
		$a_01_26 = {67 00 6c 00 6f 00 62 00 61 00 6c 00 2e 00 79 00 6d 00 74 00 72 00 61 00 63 00 6b 00 69 00 6e 00 67 00 2e 00 63 00 6f 00 6d 00 2f 00 63 00 6f 00 6e 00 76 00 3f 00 74 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 5f 00 69 00 64 00 3d 00 25 00 73 00 } //02 00 
		$a_01_27 = {26 00 6e 00 53 00 75 00 63 00 54 00 69 00 74 00 6c 00 65 00 3d 00 00 00 } //02 00 
		$a_01_28 = {68 69 64 65 69 6e 73 74 61 6c 6c 2d 74 62 00 } //02 00 
		$a_01_29 = {40 00 25 00 64 00 26 00 7a 00 3d 00 25 00 64 00 26 00 66 00 69 00 72 00 73 00 74 00 3d 00 25 00 64 00 26 00 6c 00 61 00 74 00 65 00 73 00 74 00 3d 00 25 00 64 00 00 00 } //03 00 
		$a_01_30 = {22 74 61 73 6b 55 72 69 22 20 3a 20 22 2f 75 70 2f 31 2f 72 25 64 2f 75 70 2e 62 69 6e } //00 00 
		$a_00_31 = {78 5d } //09 00 
	condition:
		any of ($a_*)
 
}
rule SoftwareBundler_Win32_SquareNet_2{
	meta:
		description = "SoftwareBundler:Win32/SquareNet,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 2b 00 00 01 00 "
		
	strings :
		$a_01_0 = {70 72 6f 66 69 74 61 62 6c 65 53 6f 66 74 55 72 6c 00 } //01 00 
		$a_01_1 = {70 72 6f 66 69 74 61 62 6c 65 73 6f 66 74 2d 73 65 61 72 63 68 00 } //01 00 
		$a_01_2 = {72 65 66 3d 25 73 26 73 69 74 65 5f 69 64 3d 25 73 26 6d 61 63 3d 25 73 26 26 73 74 65 70 3d 66 69 6e 69 73 68 00 } //02 00 
		$a_03_3 = {6f 66 66 65 72 5f 69 64 3d 90 02 08 26 61 66 66 5f 69 64 3d 90 02 10 26 74 72 61 6e 73 61 63 74 69 6f 6e 5f 69 64 90 00 } //01 00 
		$a_01_4 = {72 00 75 00 6e 00 5f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 00 00 } //01 00 
		$a_01_5 = {72 00 65 00 66 00 3d 00 25 00 73 00 26 00 6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 74 00 62 00 5f 00 73 00 74 00 61 00 74 00 65 00 3d 00 25 00 73 00 00 00 } //01 00 
		$a_01_6 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 65 00 78 00 65 00 2f 00 74 00 62 00 2f 00 66 00 62 00 3f 00 00 00 } //02 00 
		$a_03_7 = {6f 66 66 65 72 5f 69 64 3d 90 02 08 26 61 6d 70 3b 61 66 66 5f 69 64 3d 90 02 10 26 61 6d 70 3b 74 72 61 6e 73 61 63 74 69 6f 6e 5f 69 64 90 00 } //02 00 
		$a_01_8 = {5c 00 72 00 2e 00 74 00 78 00 74 00 00 00 00 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 26 00 61 00 66 00 66 00 5f 00 69 00 64 00 3d 00 00 00 00 00 26 00 74 00 72 00 61 00 6e 00 73 00 61 00 63 00 74 00 69 00 6f 00 6e 00 5f 00 69 00 64 00 3d 00 00 00 } //02 00 
		$a_01_9 = {5c 00 72 00 2e 00 74 00 78 00 74 00 00 00 00 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 72 00 65 00 66 00 3d 00 00 00 00 00 63 00 75 00 73 00 74 00 6f 00 6d 00 00 00 } //02 00 
		$a_01_10 = {2d 00 37 00 37 00 46 00 42 00 43 00 45 00 34 00 42 00 37 00 38 00 31 00 41 00 34 00 39 00 38 00 31 00 38 00 38 00 46 00 41 00 33 00 35 00 36 00 38 00 30 00 36 00 42 00 32 00 46 00 41 00 31 00 44 00 00 00 } //02 00 
		$a_01_11 = {72 00 65 00 66 00 3d 00 25 00 73 00 26 00 73 00 69 00 74 00 65 00 5f 00 69 00 64 00 3d 00 25 00 73 00 26 00 6d 00 61 00 63 00 3d 00 25 00 73 00 26 00 73 00 74 00 65 00 70 00 3d 00 64 00 62 00 6c 00 63 00 6c 00 69 00 63 00 6b 00 } //01 00 
		$a_01_12 = {2f 00 69 00 6e 00 66 00 6f 00 2e 00 64 00 61 00 74 00 00 00 } //02 00 
		$a_01_13 = {6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 72 00 65 00 66 00 3d 00 00 00 00 00 26 00 00 00 63 00 75 00 73 00 74 00 6f 00 6d 00 00 00 } //02 00 
		$a_01_14 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 00 00 } //02 00 
		$a_01_15 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2f 00 6a 00 61 00 76 00 61 00 2f 00 00 00 } //01 00 
		$a_01_16 = {2f 00 61 00 66 00 66 00 5f 00 63 00 3f 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 66 00 66 00 5f 00 69 00 64 00 3d 00 25 00 73 00 00 00 } //02 00 
		$a_01_17 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 66 00 6c 00 76 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2f 00 25 00 73 00 3f 00 25 00 73 00 00 00 } //01 00 
		$a_01_18 = {69 00 64 00 3d 00 25 00 73 00 26 00 6f 00 73 00 3d 00 25 00 73 00 26 00 70 00 3d 00 25 00 64 00 00 00 } //02 00 
		$a_01_19 = {6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 26 00 00 00 72 00 65 00 66 00 3d 00 00 00 00 00 26 00 00 00 63 00 75 00 73 00 00 00 74 00 6f 00 6d 00 00 00 } //02 00 
		$a_03_20 = {b9 3d 00 00 00 ba 25 00 00 00 66 89 4c 24 90 01 01 66 89 54 24 90 01 01 b8 64 00 00 00 b9 26 00 00 00 ba 6f 00 00 00 66 89 44 24 90 01 01 b8 73 00 00 00 90 00 } //01 00 
		$a_01_21 = {2f 00 72 00 65 00 64 00 69 00 72 00 65 00 63 00 74 00 2e 00 70 00 68 00 70 00 3f 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 00 00 } //02 00 
		$a_01_22 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 73 00 65 00 72 00 76 00 69 00 63 00 65 00 5f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 3f 00 00 00 } //02 00 
		$a_01_23 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 63 00 } //01 00 
		$a_01_24 = {2f 00 74 00 72 00 61 00 63 00 65 00 3f 00 6f 00 66 00 66 00 65 00 72 00 5f 00 69 00 64 00 3d 00 25 00 73 00 26 00 61 00 66 00 66 00 5f 00 69 00 64 00 3d 00 25 00 73 00 00 00 } //01 00 
		$a_01_25 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 47 00 65 00 74 00 20 00 49 00 6e 00 66 00 6f 00 21 00 } //02 00 
		$a_01_26 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 69 00 70 00 71 00 75 00 65 00 72 00 79 00 2f 00 67 00 65 00 74 00 5f 00 63 00 6f 00 75 00 6e 00 74 00 72 00 79 00 3f 00 69 00 70 00 3d 00 } //01 00 
		$a_01_27 = {5c 73 65 72 76 5c 64 6f 77 6e 6c 6f 61 64 2e 64 61 74 00 } //02 00 
		$a_01_28 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 69 00 5f 00 79 00 6d 00 5f 00 61 00 2e 00 65 00 78 00 65 00 00 00 } //02 00 
		$a_01_29 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00 69 00 6f 00 6e 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 63 00 75 00 73 00 74 00 6f 00 6d 00 } //01 00 
		$a_01_30 = {5c 64 6f 77 6e 6c 6f 61 64 65 72 5c 64 6f 77 6e 6c 6f 61 64 5f 6d 67 72 5c 52 65 6c 65 61 73 65 5c 6c 6f 61 64 65 72 2e 70 64 62 00 } //02 00 
		$a_01_31 = {74 00 72 00 61 00 63 00 6b 00 66 00 69 00 6c 00 65 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2e 00 63 00 6f 00 6d 00 2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 66 00 65 00 65 00 64 00 62 00 61 00 63 00 6b 00 69 00 6e 00 66 00 6f 00 2f 00 00 00 } //02 00 
		$a_01_32 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 69 00 5f 00 79 00 65 00 61 00 68 00 6d 00 6f 00 62 00 69 00 5f 00 61 00 2e 00 65 00 78 00 65 00 } //02 00 
		$a_01_33 = {74 00 72 00 61 00 63 00 6b 00 69 00 6e 00 67 00 2e 00 69 00 6d 00 6f 00 62 00 69 00 74 00 72 00 61 00 63 00 6b 00 69 00 6e 00 67 00 2e 00 6e 00 65 00 74 00 2f 00 69 00 6e 00 66 00 6f 00 2f 00 63 00 75 00 73 00 74 00 6f 00 6d 00 2f 00 } //02 00 
		$a_01_34 = {00 00 2f 00 69 00 6e 00 66 00 6f 00 2f 00 63 00 75 00 73 00 74 00 6f 00 6d 00 2f 00 63 00 70 00 78 00 69 00 } //03 00 
		$a_01_35 = {2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 69 00 5f 00 73 00 63 00 70 00 78 00 5f 00 61 00 2e 00 65 00 78 00 65 00 00 00 } //02 00 
		$a_01_36 = {60 65 2e 6d 6e 60 65 64 73 2e 68 5e 72 62 71 79 5e 60 2f 64 79 64 } //02 00 
		$a_01_37 = {60 65 2e 6d 6e 60 65 64 73 2e 68 5e 78 64 60 69 6c 6e 63 68 5e 60 2f 64 79 64 } //02 00 
		$a_03_38 = {8b 45 08 8a 04 07 32 45 10 0f b6 c0 50 e8 90 01 04 47 3b 7d 0c 72 e8 90 00 } //02 00 
		$a_03_39 = {39 7d 0c 76 14 8b 45 90 01 01 8a 1c 38 32 5d 10 e8 90 01 04 47 3b 7d 0c 72 ec 90 00 } //02 00 
		$a_01_40 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 69 00 6e 00 66 00 6f 00 6d 00 67 00 72 00 2f 00 73 00 76 00 63 00 2f 00 73 00 76 00 63 00 69 00 6e 00 66 00 6f 00 3f 00 } //02 00 
		$a_01_41 = {5c 64 6f 77 6e 6c 6f 61 64 5f 6d 67 72 5f 70 68 6f 74 6f 79 65 65 5c 52 65 6c 65 61 73 65 5c } //02 00 
		$a_01_42 = {2f 00 65 00 6e 00 74 00 72 00 79 00 2f 00 74 00 72 00 61 00 63 00 6b 00 2f 00 65 00 76 00 65 00 6e 00 74 00 2d 00 66 00 62 00 3f 00 } //00 00 
		$a_00_43 = {7e } //15 00 
	condition:
		any of ($a_*)
 
}