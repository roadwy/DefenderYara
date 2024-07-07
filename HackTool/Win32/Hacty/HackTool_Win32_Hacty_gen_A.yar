
rule HackTool_Win32_Hacty_gen_A{
	meta:
		description = "HackTool:Win32/Hacty.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,19 00 14 00 1a 00 00 "
		
	strings :
		$a_02_0 = {4c 6f 61 64 65 72 3e 20 48 6f 6f 6b 20 73 68 6f 75 6c 64 20 62 65 20 73 65 74 20 6e 6f 77 90 02 10 4c 6f 61 64 65 72 3e 20 43 61 6c 6c 69 6e 67 20 6c 6f 61 64 20 66 75 6e 63 74 69 6f 6e 90 02 10 4c 6f 61 64 65 72 3e 20 46 41 49 4c 45 44 90 00 } //10
		$a_02_1 = {53 65 74 55 70 48 6f 6f 6b 90 02 05 4c 6f 61 64 65 72 3e 20 52 65 73 6f 6c 76 69 6e 67 20 6c 6f 61 64 20 66 75 6e 63 74 69 6f 6e 90 02 10 4e 74 49 6c 6c 75 73 69 6f 6e 90 02 02 64 6c 6c 90 02 02 4c 6f 61 64 65 72 3e 20 6c 6f 61 64 69 6e 67 20 4e 54 49 6c 6c 75 73 69 6f 6e 90 00 } //10
		$a_00_2 = {4e 00 54 00 49 00 6c 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 2e 00 64 00 6c 00 6c 00 } //5 NTIllusion.dll
		$a_00_3 = {56 61 6e 71 75 69 73 68 20 2d 20 44 4c 4c 20 69 6e 6a 65 63 74 69 6f 6e 20 66 61 69 6c 65 64 3a } //3 Vanquish - DLL injection failed:
		$a_00_4 = {50 72 65 70 61 72 65 20 69 6e 6a 65 63 74 6f 72 20 66 61 69 6c 65 64 21 20 43 61 6e 6e 6f 74 20 66 69 6e 64 20 61 64 64 72 65 73 73 20 6f 66 20 4c 6f 61 64 4c 69 62 72 61 72 79 57 } //3 Prepare injector failed! Cannot find address of LoadLibraryW
		$a_00_5 = {55 6e 68 61 6e 64 6c 65 64 20 65 78 63 65 70 74 69 6f 6e 20 63 61 75 67 68 74 21 20 50 6c 65 61 73 65 20 66 6f 72 77 61 72 64 20 74 68 69 73 20 69 6e 66 6f 72 6d 61 74 69 6f 6e 20 74 6f 20 74 68 65 20 61 75 74 68 6f 72 } //3 Unhandled exception caught! Please forward this information to the author
		$a_00_6 = {2a 2a 2a 41 70 70 6c 69 63 61 74 69 6f 6e 3a 20 25 73 } //1 ***Application: %s
		$a_00_7 = {2a 2a 2a 54 69 6d 65 3a 20 25 73 } //1 ***Time: %s
		$a_00_8 = {2a 2a 2a 44 61 74 65 3a 20 25 73 } //1 ***Date: %s
		$a_00_9 = {56 61 6e 71 75 69 73 68 20 41 75 74 6f 6c 6f 61 64 65 72 20 76 30 2e 31 20 62 65 74 61 31 30 } //5 Vanquish Autoloader v0.1 beta10
		$a_00_10 = {43 61 6e 6e 6f 74 20 6f 70 65 6e 20 53 43 4d 21 20 4d 61 79 62 65 20 6e 6f 74 20 61 64 6d 69 6e 21 3f } //3 Cannot open SCM! Maybe not admin!?
		$a_00_11 = {43 61 6e 6e 6f 74 20 6f 70 65 6e 20 56 61 6e 71 75 69 73 68 20 53 65 72 76 69 63 65 21 20 4d 61 79 62 65 20 6e 6f 74 20 69 6e 73 74 61 6c 6c 65 64 21 3f } //3 Cannot open Vanquish Service! Maybe not installed!?
		$a_00_12 = {56 00 61 00 6e 00 71 00 75 00 69 00 73 00 68 00 41 00 75 00 74 00 6f 00 49 00 6e 00 6a 00 65 00 63 00 74 00 69 00 6e 00 67 00 44 00 4c 00 4c 00 } //3 VanquishAutoInjectingDLL
		$a_00_13 = {46 61 69 6c 65 64 20 74 6f 20 69 6e 6a 65 63 74 20 56 41 4e 51 55 49 53 48 21 } //2 Failed to inject VANQUISH!
		$a_00_14 = {4c 75 63 6b 79 21 20 4c 75 63 6b 79 21 20 42 79 20 72 65 74 72 79 69 6e 67 20 49 20 6d 61 6e 61 67 65 64 20 74 6f 20 61 76 6f 69 64 20 6f 76 65 72 66 6c 6f 77 69 6e 67 20 74 68 65 20 49 6e 64 65 78 6f 72 } //2 Lucky! Lucky! By retrying I managed to avoid overflowing the Indexor
		$a_00_15 = {47 65 65 21 20 4f 76 65 72 66 6c 6f 77 65 64 20 74 68 65 20 49 6e 64 65 78 6f 72 21 20 48 69 64 64 65 6e 20 72 65 67 69 73 74 72 79 20 76 61 6c 75 65 73 20 6d 61 79 20 73 68 6f 77 20 75 70 } //2 Gee! Overflowed the Indexor! Hidden registry values may show up
		$a_00_16 = {4f 6f 70 73 21 20 4f 76 65 72 66 6c 6f 77 65 64 20 64 77 49 6e 64 65 78 4b 45 59 21 20 53 6f 6d 65 20 6b 65 79 73 20 77 69 6c 6c 20 6e 6f 74 20 73 68 6f 77 20 75 70 } //2 Oops! Overflowed dwIndexKEY! Some keys will not show up
		$a_00_17 = {4f 6f 70 73 21 20 4f 76 65 72 66 6c 6f 77 65 64 20 64 77 49 6e 64 65 78 56 41 4c 21 20 53 6f 6d 65 20 76 61 6c 75 65 73 20 77 69 6c 6c 20 6e 6f 74 20 73 68 6f 77 20 75 70 } //2 Oops! Overflowed dwIndexVAL! Some values will not show up
		$a_00_18 = {46 69 6e 61 6c 6c 79 20 73 6f 6d 65 62 6f 64 79 20 69 6e 76 6f 6b 65 64 20 52 65 67 51 75 65 72 79 4d 75 6c 74 69 70 6c 65 56 61 6c 75 65 73 57 } //2 Finally somebody invoked RegQueryMultipleValuesW
		$a_00_19 = {46 69 6e 61 6c 6c 79 20 73 6f 6d 65 62 6f 64 79 20 69 6e 76 6f 6b 65 64 20 52 65 67 51 75 65 72 79 4d 75 6c 74 69 70 6c 65 56 61 6c 75 65 73 41 } //2 Finally somebody invoked RegQueryMultipleValuesA
		$a_00_20 = {45 72 72 6f 72 20 61 6c 6c 6f 63 61 74 69 6e 67 20 25 75 20 62 79 74 65 73 20 69 6e 20 45 6e 75 6d 53 65 72 76 69 63 65 53 74 61 74 75 73 41 } //2 Error allocating %u bytes in EnumServiceStatusA
		$a_00_21 = {4e 6f 74 20 61 62 6c 65 20 74 6f 20 45 6e 75 6d 53 65 72 76 69 63 65 73 41 20 70 72 6f 70 65 72 6c 79 20 28 6e 65 65 64 20 61 64 64 69 74 69 6f 6e 61 6c 20 25 75 20 62 79 74 65 73 29 } //2 Not able to EnumServicesA properly (need additional %u bytes)
		$a_00_22 = {45 72 72 6f 72 20 61 6c 6c 6f 63 61 74 69 6e 67 20 25 75 20 62 79 74 65 73 20 69 6e 20 45 6e 75 6d 53 65 72 76 69 63 65 53 74 61 74 75 73 57 } //2 Error allocating %u bytes in EnumServiceStatusW
		$a_00_23 = {4e 6f 74 20 61 62 6c 65 20 74 6f 20 45 6e 75 6d 53 65 72 76 69 63 65 73 57 20 70 72 6f 70 65 72 6c 79 20 28 6e 65 65 64 20 61 64 64 69 74 69 6f 6e 61 6c 20 25 75 20 62 79 74 65 73 29 } //2 Not able to EnumServicesW properly (need additional %u bytes)
		$a_00_24 = {59 6f 75 20 63 61 6e 6e 6f 74 20 6d 6f 64 69 66 79 20 73 79 73 74 65 6d 20 74 69 6d 65 21 20 49 6e 73 74 65 61 64 2c 20 79 6f 75 72 20 61 74 74 65 6d 70 74 20 68 61 73 20 62 65 65 6e 20 6c 6f 67 67 65 64 20 3a 29 } //2 You cannot modify system time! Instead, your attempt has been logged :)
		$a_00_25 = {59 6f 75 20 63 61 6e 6e 6f 74 20 64 65 6c 65 74 65 20 70 72 6f 74 65 63 74 65 64 20 66 69 6c 65 73 2f 66 6f 6c 64 65 72 73 21 20 49 6e 73 74 65 61 64 2c 20 79 6f 75 72 20 61 74 74 65 6d 70 74 20 68 61 73 20 62 65 65 6e 20 6c 6f 67 67 65 64 20 3a 29 } //2 You cannot delete protected files/folders! Instead, your attempt has been logged :)
	condition:
		((#a_02_0  & 1)*10+(#a_02_1  & 1)*10+(#a_00_2  & 1)*5+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3+(#a_00_5  & 1)*3+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*5+(#a_00_10  & 1)*3+(#a_00_11  & 1)*3+(#a_00_12  & 1)*3+(#a_00_13  & 1)*2+(#a_00_14  & 1)*2+(#a_00_15  & 1)*2+(#a_00_16  & 1)*2+(#a_00_17  & 1)*2+(#a_00_18  & 1)*2+(#a_00_19  & 1)*2+(#a_00_20  & 1)*2+(#a_00_21  & 1)*2+(#a_00_22  & 1)*2+(#a_00_23  & 1)*2+(#a_00_24  & 1)*2+(#a_00_25  & 1)*2) >=20
 
}