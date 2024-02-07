
rule Trojan_Win32_Ragzil_B{
	meta:
		description = "Trojan:Win32/Ragzil.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 76 6d 74 2e 65 78 65 } //01 00  .vmt.exe
		$a_01_1 = {2f 65 6e 63 2e 65 78 65 } //01 00  /enc.exe
		$a_01_2 = {61 6e 74 69 5f 76 6d 5f 65 78 63 6c 75 73 69 6f 6e 5f 6e 61 6d 65 } //01 00  anti_vm_exclusion_name
		$a_01_3 = {61 64 64 5f 66 6f 6c 64 65 72 5f 74 6f 5f 65 78 63 6c 75 73 69 6f 6e 73 } //01 00  add_folder_to_exclusions
		$a_01_4 = {73 74 61 72 74 5f 69 6e 5f 6d 65 6d 6f 72 79 5f 70 61 74 68 } //01 00  start_in_memory_path
		$a_01_5 = {70 75 6d 70 5f 66 69 6c 65 } //00 00  pump_file
	condition:
		any of ($a_*)
 
}