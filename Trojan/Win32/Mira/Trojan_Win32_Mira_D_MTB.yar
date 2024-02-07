
rule Trojan_Win32_Mira_D_MTB{
	meta:
		description = "Trojan:Win32/Mira.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 72 00 61 00 20 00 4d 00 61 00 6c 00 77 00 61 00 72 00 65 00 00 00 00 00 38 00 0a 00 01 00 50 00 72 } //01 00 
		$a_01_1 = {5c 41 6c 6c 20 55 73 65 72 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 53 61 61 61 61 6c 61 6d 6d 5c 4d 69 72 61 2e 68 } //01 00  \All Users\Application Data\Saaaalamm\Mira.h
		$a_01_2 = {2f 6d 6e 74 2f 73 61 6d 6f 2f 6d 69 6e 67 77 2f 6d 73 79 73 2f 6d 74 68 72 5f 73 74 75 62 2e 63 } //01 00  /mnt/samo/mingw/msys/mthr_stub.c
		$a_01_3 = {5c 41 6c 6c 20 55 73 65 72 73 5c 41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 78 69 6e 73 62 70 2e 65 78 65 } //00 00  \All Users\Application Data\xinsbp.exe
		$a_00_4 = {5d 04 00 } //00 a0 
	condition:
		any of ($a_*)
 
}