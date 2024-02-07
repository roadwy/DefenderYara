
rule Trojan_Win32_Corebot_C_bit{
	meta:
		description = "Trojan:Win32/Corebot.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {66 6b 69 74 2e 70 64 62 } //02 00  fkit.pdb
		$a_01_1 = {64 66 37 36 38 39 65 36 2d 63 34 39 66 2d 34 61 38 36 2d 38 32 65 38 2d 36 38 30 39 61 34 30 36 38 37 32 61 } //01 00  df7689e6-c49f-4a86-82e8-6809a406872a
		$a_01_2 = {63 6f 72 65 2e 70 6c 75 67 69 6e 73 5f 6b 65 79 } //01 00  core.plugins_key
		$a_01_3 = {63 6f 72 65 2e 69 6e 6a 65 63 74 } //01 00  core.inject
		$a_01_4 = {63 6f 72 65 2e 73 65 72 76 65 72 73 } //01 00  core.servers
		$a_01_5 = {63 6f 72 65 2e 69 6e 73 74 61 6c 6c 65 64 5f 66 69 6c 65 } //00 00  core.installed_file
		$a_00_6 = {5d 04 00 } //00 4b 
	condition:
		any of ($a_*)
 
}