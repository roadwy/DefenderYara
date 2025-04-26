
rule VirTool_Win32_Bruterat_B{
	meta:
		description = "VirTool:Win32/Bruterat.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0d 00 00 "
		
	strings :
		$a_01_0 = {54 ca af 91 } //1
		$a_01_1 = {a1 6a 3d d8 } //1
		$a_01_2 = {94 9b 15 d5 } //1
		$a_01_3 = {b6 19 18 e7 } //1
		$a_01_4 = {a4 19 70 e9 } //1
		$a_80_5 = {5d 20 45 6c 65 76 61 74 65 64 } //] Elevated  1
		$a_80_6 = {5d 20 49 6e 6a 65 63 74 65 64 } //] Injected  1
		$a_80_7 = {5d 20 53 70 6f 6f 66 65 64 } //] Spoofed  1
		$a_80_8 = {5d 20 54 43 50 20 6c 69 73 74 65 6e 65 72 20 73 74 61 72 74 65 64 } //] TCP listener started  1
		$a_80_9 = {5d 20 41 63 63 6f 75 6e 74 20 4c 6f 63 6b 6f 75 74 20 50 6f 6c 69 63 79 } //] Account Lockout Policy  1
		$a_80_10 = {5d 20 55 73 65 72 20 68 61 73 20 41 64 6d 69 6e 20 70 72 69 76 69 6c 65 67 65 } //] User has Admin privilege  1
		$a_80_11 = {5d 20 53 63 72 65 65 6e 73 68 6f 74 20 64 6f 77 6e 6c 6f 61 64 65 64 3a } //] Screenshot downloaded:  1
		$a_80_12 = {5d 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 } //] Impersonated  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=12
 
}
rule VirTool_Win32_Bruterat_B_2{
	meta:
		description = "VirTool:Win32/Bruterat.B,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0d 00 00 "
		
	strings :
		$a_01_0 = {54 ca af 91 } //1
		$a_01_1 = {a1 6a 3d d8 } //1
		$a_01_2 = {94 9b 15 d5 } //1
		$a_01_3 = {b6 19 18 e7 } //1
		$a_01_4 = {a4 19 70 e9 } //1
		$a_80_5 = {5d 20 53 41 4d 20 55 73 65 72 6e 61 6d 65 3a } //] SAM Username:  1
		$a_80_6 = {5d 20 55 73 65 72 20 69 73 20 70 72 69 76 69 6c 65 67 65 64 } //] User is privileged  1
		$a_80_7 = {5d 20 41 6c 65 72 74 61 62 6c 65 20 74 68 72 65 61 64 3a } //] Alertable thread:  1
		$a_80_8 = {5d 20 45 6c 65 76 61 74 65 64 20 50 72 69 76 69 6c 65 67 65 } //] Elevated Privilege  1
		$a_80_9 = {5d 20 53 63 72 65 65 6e 73 68 6f 74 20 64 6f 77 6e 6c 6f 61 64 65 64 3a } //] Screenshot downloaded:  1
		$a_80_10 = {5d 20 49 6d 70 65 72 73 6f 6e 61 74 65 64 } //] Impersonated  1
		$a_80_11 = {5d 20 41 4d 53 49 20 70 61 74 63 68 65 64 } //] AMSI patched  1
		$a_80_12 = {5d 20 53 79 6e 63 69 6e 67 20 44 43 3a } //] Syncing DC:  1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1+(#a_80_12  & 1)*1) >=12
 
}