
rule Backdoor_Win32_NetWiredRC_MTB{
	meta:
		description = "Backdoor:Win32/NetWiredRC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 1c 17 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 31 f3 81 ?? ?? ?? ?? ?? 81 ?? ?? ?? ?? ?? 01 1c 10 } //5
		$a_00_1 = {4c 00 45 00 6f 00 43 00 77 00 66 00 37 00 37 00 65 00 48 00 65 00 76 00 31 00 46 00 45 00 46 00 43 00 30 00 77 00 47 00 59 00 57 00 5a 00 46 00 38 00 6d 00 66 00 42 00 71 00 6d 00 4c 00 43 00 32 00 32 00 39 00 } //5 LEoCwf77eHev1FEFC0wGYWZF8mfBqmLC229
		$a_00_2 = {69 00 70 00 49 00 4a 00 35 00 6b 00 68 00 6b 00 4d 00 33 00 33 00 75 00 30 00 71 00 5a 00 4a 00 69 00 48 00 56 00 56 00 38 00 68 00 64 00 39 00 67 00 47 00 51 00 55 00 69 00 35 00 39 00 } //5 ipIJ5khkM33u0qZJiHVV8hd9gGQUi59
	condition:
		((#a_03_0  & 1)*5+(#a_00_1  & 1)*5+(#a_00_2  & 1)*5) >=15
 
}