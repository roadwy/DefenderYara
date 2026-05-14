
rule Trojan_Win32_Fragtor_PGFT_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.PGFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_80_0 = {64 72 69 76 65 2e 75 73 65 72 63 6f 6e 74 65 6e 74 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 3f 69 64 3d 31 59 42 56 49 44 6b 5a 67 79 67 4e 66 55 55 32 72 62 4a 58 58 43 59 64 72 7a 61 79 35 72 4d 64 59 26 65 78 70 6f 72 74 3d 64 6f 77 6e 6c 6f 61 64 26 61 75 74 68 75 73 65 72 3d 30 26 63 6f 6e 66 69 72 6d 3d 74 00 2f 73 65 72 76 69 63 65 } //drive.usercontent.google.com/download?id=1YBVIDkZgygNfUU2rbJXXCYdrzay5rMdY&export=download&authuser=0&confirm=t  5
		$a_80_1 = {30 4a 37 45 46 47 41 42 43 65 75 76 64 44 4b 34 38 39 53 45 56 35 36 65 77 66 33 33 32 4e 64 31 32 33 73 66 65 57 34 77 65 72 66 35 46 44 47 77 59 5a 52 74 77 7a } //0J7EFGABCeuvdDK489SEV56ewf332Nd123sfeW4werf5FDGwYZRtwz  5
	condition:
		((#a_80_0  & 1)*5+(#a_80_1  & 1)*5) >=10
 
}