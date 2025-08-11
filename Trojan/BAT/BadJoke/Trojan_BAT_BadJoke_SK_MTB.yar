
rule Trojan_BAT_BadJoke_SK_MTB{
	meta:
		description = "Trojan:BAT/BadJoke.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 65 33 64 34 65 35 62 63 2d 32 35 30 30 2d 34 64 63 34 2d 61 33 66 62 2d 31 37 30 38 32 33 35 36 30 38 65 64 } //1 $e3d4e5bc-2500-4dc4-a3fb-1708235608ed
		$a_81_1 = {41 4c 4f 4e 45 5f 44 45 53 54 52 55 43 54 49 56 45 2e 52 65 73 6f 75 72 63 65 73 } //1 ALONE_DESTRUCTIVE.Resources
		$a_81_2 = {41 4c 4f 4e 45 40 44 45 53 54 55 52 43 54 49 56 45 } //1 ALONE@DESTURCTIVE
		$a_81_3 = {53 69 74 20 64 6f 77 6e 20 61 6e 64 20 77 61 74 63 68 20 61 6c 6c 20 79 6f 75 27 72 65 20 66 69 6c 65 20 62 65 67 69 6e 20 64 65 6c 65 74 65 64 } //1 Sit down and watch all you're file begin deleted
		$a_81_4 = {44 69 73 61 62 6c 65 54 61 73 6b 4d 67 72 } //1 DisableTaskMgr
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}