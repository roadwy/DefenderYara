
rule Trojan_Win64_Tedy_AHA_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 f0 80 f1 ?? 48 83 7d 08 0f 48 0f 47 45 f0 42 88 0c 08 49 ff c1 48 8b 4d 00 4c 3b c9 72 } //30
		$a_01_1 = {47 6c 6f 62 61 6c 5c 57 69 64 67 65 74 73 50 6c 61 74 66 6f 72 6d 4d 75 74 65 78 } //20 Global\WidgetsPlatformMutex
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}