
rule Trojan_BAT_DefenseEvasion_RK_MTB{
	meta:
		description = "Trojan:BAT/DefenseEvasion.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {55 30 56 4d 52 55 4e 55 49 48 42 68 63 33 4e 33 62 33 4a 6b 58 33 5a 68 62 48 56 6c 4c 48 56 7a 5a 58 4a 75 59 57 31 6c 58 33 5a 68 62 48 56 6c 4c 47 39 79 61 57 64 70 62 6c 39 31 63 6d 77 67 52 6c 4a 50 54 53 42 73 62 32 64 70 62 6e 4d 3d } //U0VMRUNUIHBhc3N3b3JkX3ZhbHVlLHVzZXJuYW1lX3ZhbHVlLG9yaWdpbl91cmwgRlJPTSBsb2dpbnM=  1
		$a_80_1 = {59 32 68 79 62 32 31 6c 58 45 78 76 5a 32 6c 75 49 45 52 68 64 47 45 3d } //Y2hyb21lXExvZ2luIERhdGE=  1
		$a_80_2 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //DisableAntiSpyware  1
		$a_80_3 = {44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 } //DisableBehaviorMonitoring  1
		$a_80_4 = {73 74 6f 70 5f 77 69 6e 64 6f 77 73 5f 64 65 66 65 6e 64 65 72 } //stop_windows_defender  1
		$a_80_5 = {44 69 73 61 62 6c 65 53 63 61 6e 4f 6e 52 65 61 6c 74 69 6d 65 45 6e 61 62 6c 65 } //DisableScanOnRealtimeEnable  1
		$a_80_6 = {61 48 52 30 63 44 6f 76 4c 32 78 76 59 32 46 73 61 47 39 7a 64 43 39 30 5a 58 4e 30 4c 33 42 70 62 6d 63 75 63 47 68 77 } //aHR0cDovL2xvY2FsaG9zdC90ZXN0L3BpbmcucGhw  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}