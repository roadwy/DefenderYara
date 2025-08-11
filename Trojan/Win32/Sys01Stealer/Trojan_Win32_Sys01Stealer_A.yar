
rule Trojan_Win32_Sys01Stealer_A{
	meta:
		description = "Trojan:Win32/Sys01Stealer.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {3f 6d 61 63 68 69 6e 65 5f 69 64 3d 24 6d 61 63 68 69 6e 65 49 64 26 } //?machine_id=$machineId&  1
		$a_80_1 = {3f 61 3d 68 74 74 70 26 64 65 76 3d 31 26 } //?a=http&dev=1&  1
		$a_80_2 = {26 76 3d 7b 24 63 6f 6e 66 69 67 5b 27 76 65 72 73 69 6f 6e 27 5d 7d 26 } //&v={$config['version']}&  1
		$a_80_3 = {42 72 6f 77 73 65 72 28 42 72 6f 77 73 65 72 3a 3a 42 41 53 45 44 5f 43 48 52 4f 4d 45 4d 49 55 4d 2c } //Browser(Browser::BASED_CHROMEMIUM,  1
		$a_80_4 = {42 72 6f 77 73 65 72 28 42 72 6f 77 73 65 72 3a 3a 42 41 53 45 44 5f 4d 4f 5a 2c } //Browser(Browser::BASED_MOZ,  1
		$a_80_5 = {73 68 65 6c 6c 5f 65 78 65 63 28 24 63 29 } //shell_exec($c)  1
		$a_80_6 = {24 74 61 73 6b 2d 3e 73 61 76 65 5f 74 6f 5f 63 75 72 72 65 6e 74 5f 77 6f 72 6b } //$task->save_to_current_work  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}