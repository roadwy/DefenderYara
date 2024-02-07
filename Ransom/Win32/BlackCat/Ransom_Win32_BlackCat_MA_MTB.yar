
rule Ransom_Win32_BlackCat_MA_MTB{
	meta:
		description = "Ransom:Win32/BlackCat.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {24 7b 4e 4f 54 45 5f 46 49 4c 45 5f 4e 41 4d 45 7d } //02 00  ${NOTE_FILE_NAME}
		$a_01_1 = {5f 63 69 70 68 65 72 6b 69 6c 6c 5f 73 65 72 76 69 63 65 73 6b 69 6c 6c 5f 70 72 6f 63 65 73 73 65 73 65 78 63 6c 75 64 65 } //02 00  _cipherkill_serviceskill_processesexclude
		$a_01_2 = {5f 6e 65 74 77 6f 72 6b 5f 64 69 73 63 6f 76 65 72 79 65 6e 61 62 6c 65 5f 73 65 6c 66 } //02 00  _network_discoveryenable_self
		$a_01_3 = {5f 77 61 6c 6c 70 61 70 65 72 65 6e 61 62 6c 65 5f 65 73 78 69 5f 76 6d 5f 6b 69 6c 6c 65 6e 61 62 6c 65 5f 65 73 78 69 5f 76 6d 5f 73 6e 61 70 73 68 6f 74 } //02 00  _wallpaperenable_esxi_vm_killenable_esxi_vm_snapshot
		$a_01_4 = {5f 6b 69 6c 6c 73 74 72 69 63 74 5f 69 6e 63 6c 75 64 65 5f 70 61 74 68 73 65 73 78 69 5f 76 6d 5f 6b 69 6c 6c 5f 65 78 63 6c 75 64 65 73 6c 65 65 70 5f 72 65 73 74 61 72 74 } //00 00  _killstrict_include_pathsesxi_vm_kill_excludesleep_restart
	condition:
		any of ($a_*)
 
}