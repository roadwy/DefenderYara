
rule Backdoor_Win32_NetWolf_A{
	meta:
		description = "Backdoor:Win32/NetWolf.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 0c 06 80 f1 43 88 08 40 4f 75 f4 } //01 00 
		$a_01_1 = {8b 41 04 89 42 04 8b 41 08 89 42 08 8b 49 0c 89 4a 0c 8b 53 20 } //01 00 
		$a_00_2 = {2d 53 76 72 20 5b 6c 69 73 74 5d 20 7c 20 5b 5b 69 6e 66 6f 5d 20 7c 20 5b 73 74 61 72 74 7c 73 74 6f 70 7c 64 65 6c 65 74 65 7c 72 65 73 74 61 72 74 5d } //01 00  -Svr [list] | [[info] | [start|stop|delete|restart]
		$a_00_3 = {2d 73 65 74 20 4d 61 69 6c 09 6d 61 69 6c 20 20 70 61 73 73 77 6f 72 64 } //01 00  猭瑥䴠楡६慭汩†慰獳潷摲
		$a_00_4 = {2d 73 65 74 20 48 74 74 70 50 72 6f 78 79 09 69 70 20 70 6f 72 74 } //00 00  猭瑥䠠瑴偰潲祸椉⁰潰瑲
	condition:
		any of ($a_*)
 
}