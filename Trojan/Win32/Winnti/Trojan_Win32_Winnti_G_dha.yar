
rule Trojan_Win32_Winnti_G_dha{
	meta:
		description = "Trojan:Win32/Winnti.G!dha,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5b 77 64 5d 3a 52 65 6d 6f 74 65 49 6e 6a 65 63 74 20 25 73 } //01 00  [wd]:RemoteInject %s
		$a_01_1 = {5b 77 64 5d 64 65 6c 65 74 65 6d 65 43 6d 64 3a 25 73 } //01 00  [wd]deletemeCmd:%s
		$a_01_2 = {64 65 6c 20 25 25 30 00 2e 62 61 74 } //01 00 
		$a_01_3 = {77 69 6e 64 30 77 73 00 53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 25 73 } //00 00  楷摮眰s奓呓䵅䍜牵敲瑮潃瑮潲卬瑥卜牥楶散屳猥
		$a_01_4 = {00 67 } //16 00  最
	condition:
		any of ($a_*)
 
}