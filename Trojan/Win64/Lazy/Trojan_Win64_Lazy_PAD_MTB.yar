
rule Trojan_Win64_Lazy_PAD_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 8b 4d b8 0f b6 14 81 88 55 a0 0f b6 45 a1 44 0f b6 0c 81 44 88 4d a1 0f b6 45 a2 0f b6 34 81 40 88 75 a2 } //3
		$a_00_1 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //2 DisableRealtimeMonitoring
		$a_00_2 = {44 69 73 61 62 6c 65 42 65 68 61 76 69 6f 72 4d 6f 6e 69 74 6f 72 69 6e 67 } //2 DisableBehaviorMonitoring
		$a_00_3 = {44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 } //2 DisableAntiSpyware
		$a_00_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 45 78 63 6c 75 73 69 6f 6e 73 5c 50 61 74 68 73 } //1 SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths
	condition:
		((#a_01_0  & 1)*3+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1) >=10
 
}