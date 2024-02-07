
rule Trojan_Win32_Qakbot_CI_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 5f 63 6c 65 61 6e 5f 74 79 70 65 5f 69 6e 66 6f 5f 6e 61 6d 65 73 5f 69 6e 74 65 72 6e 61 6c } //01 00  S_clean_type_info_names_internal
		$a_01_1 = {53 5f 5f 75 6e 67 75 61 72 64 65 64 5f 72 65 61 64 6c 63 5f 61 63 74 69 76 65 5f 61 64 64 5f 66 75 6e 63 } //01 00  S__unguarded_readlc_active_add_func
		$a_01_2 = {53 5f 43 78 78 55 6e 72 65 67 69 73 74 65 72 45 78 63 65 70 74 69 6f 6e 4f 62 6a 65 63 74 } //01 00  S_CxxUnregisterExceptionObject
		$a_01_3 = {53 55 6e 6c 6f 63 6b 5f 73 68 61 72 65 64 5f 70 74 72 5f 73 70 69 6e 5f 6c 6f 63 6b } //01 00  SUnlock_shared_ptr_spin_lock
		$a_01_4 = {53 4c 6f 63 6b 5f 73 68 61 72 65 64 5f 70 74 72 5f 73 70 69 6e 5f 6c 6f 63 6b } //01 00  SLock_shared_ptr_spin_lock
		$a_01_5 = {53 77 68 61 74 40 65 78 63 65 70 74 69 6f 6e 40 73 74 64 40 40 55 42 45 50 42 44 58 5a } //01 00  Swhat@exception@std@@UBEPBDXZ
		$a_01_6 = {53 74 72 79 5f 6c 6f 63 6b 40 63 72 69 74 69 63 61 6c 5f 73 65 63 74 69 6f 6e 40 43 6f 6e 63 75 72 72 65 6e 63 79 40 40 51 41 45 5f 4e 58 5a } //01 00  Stry_lock@critical_section@Concurrency@@QAE_NXZ
		$a_01_7 = {53 6c 6f 63 6b 40 72 65 61 64 65 72 5f 77 72 69 74 65 72 5f 6c 6f 63 6b 40 43 6f 6e 63 75 72 72 65 6e 63 79 40 40 51 41 45 58 58 5a } //01 00  Slock@reader_writer_lock@Concurrency@@QAEXXZ
		$a_01_8 = {53 69 73 6d 62 62 6b 61 6c 6e 75 6d 5f 6c } //01 00  Sismbbkalnum_l
		$a_01_9 = {53 73 65 68 5f 6c 6f 6e 67 6a 6d 70 5f 75 6e 77 69 6e 64 } //01 00  Sseh_longjmp_unwind
		$a_01_10 = {53 6f 63 61 6c 65 63 6f 6e 76 } //01 00  Socaleconv
		$a_01_11 = {53 65 78 65 63 76 70 65 } //00 00  Sexecvpe
	condition:
		any of ($a_*)
 
}