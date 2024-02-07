
rule Trojan_Win32_ExaramaDl_B{
	meta:
		description = "Trojan:Win32/ExaramaDl.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {5f 5f 73 68 6d 65 6d 33 5f 77 69 6e 70 74 68 72 65 61 64 73 5f 74 64 6d 5f } //01 00  __shmem3_winpthreads_tdm_
		$a_00_1 = {3c 75 72 6c 3e 20 3c 66 69 6c 65 70 61 74 68 3e } //01 00  <url> <filepath>
		$a_00_2 = {69 6e 76 6f 6b 69 6e 67 20 45 78 61 72 61 6d 65 6c 20 44 4c 4c 20 76 69 61 } //01 00  invoking Exaramel DLL via
		$a_00_3 = {5b 69 5d 20 44 6f 77 6e 6c 6f 61 64 69 6e 67 20 66 69 6c 65 3a } //01 00  [i] Downloading file:
		$a_03_4 = {83 e0 0f 41 c0 e8 04 83 c0 61 41 83 c0 41 88 42 ff 44 88 42 fe 4c 39 c9 75 d8 48 8d 05 90 01 04 b9 5f 00 00 00 48 8d 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}