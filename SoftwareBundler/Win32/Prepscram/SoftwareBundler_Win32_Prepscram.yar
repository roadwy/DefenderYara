
rule SoftwareBundler_Win32_Prepscram{
	meta:
		description = "SoftwareBundler:Win32/Prepscram,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 02 00 00 00 80 34 30 90 01 01 83 c0 03 3d 90 01 04 72 f2 8b 47 08 68 00 b0 00 00 ff 70 04 ff d6 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule SoftwareBundler_Win32_Prepscram_2{
	meta:
		description = "SoftwareBundler:Win32/Prepscram,SIGNATURE_TYPE_PEHSTR_EXT,21 00 21 00 04 00 00 "
		
	strings :
		$a_01_0 = {00 54 65 72 6d 69 6e 61 74 65 64 00 } //16 吀牥業慮整d
		$a_01_1 = {00 31 32 30 00 2f 52 45 43 45 49 56 45 54 49 4d 45 4f 55 54 00 31 35 00 2f 43 4f 4e 4e 45 43 54 54 49 4d 45 4f 55 54 00 2f 4e 4f 43 41 4e 43 45 4c 00 2f 53 49 4c 45 4e 54 00 67 65 74 00 } //16
		$a_00_2 = {3a 2f 2f 6a 75 6d 70 2e 6d 69 6c 6b 63 6f 6f 6b 2e 62 69 64 2f } //1 ://jump.milkcook.bid/
		$a_00_3 = {3a 2f 2f 66 6c 69 70 69 74 2e 62 61 67 61 6d 75 73 65 6d 65 6e 74 2e 62 69 64 2f } //1 ://flipit.bagamusement.bid/
	condition:
		((#a_01_0  & 1)*16+(#a_01_1  & 1)*16+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=33
 
}