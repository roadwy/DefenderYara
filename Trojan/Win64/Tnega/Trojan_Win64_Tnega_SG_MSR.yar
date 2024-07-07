
rule Trojan_Win64_Tnega_SG_MSR{
	meta:
		description = "Trojan:Win64/Tnega.SG!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_80_0 = {6f 67 64 33 36 38 68 63 2e 64 6c 6c } //ogd368hc.dll  1
		$a_80_1 = {49 42 45 5a 64 35 39 45 } //IBEZd59E  1
		$a_80_2 = {32 47 6c 6f 72 69 6f 75 73 20 25 73 20 49 6e 76 65 73 74 69 67 61 74 65 2b 20 25 64 40 20 65 73 74 61 74 65 28 20 50 69 67 20 44 65 63 6c 61 72 65 64 28 27 43 6f 6e 66 65 73 73 69 6f 6e 29 20 61 6e 67 65 6c 20 69 6e 74 65 72 76 65 6e 74 69 6f 6e 24 20 77 6f 6c 76 65 73 20 } //2Glorious %s Investigate+ %d@ estate( Pig Declared('Confession) angel intervention$ wolves   1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //VirtualAlloc  1
		$a_80_4 = {46 69 6e 64 46 69 72 73 74 46 69 6c 65 41 } //FindFirstFileA  1
		$a_80_5 = {46 69 6e 64 4e 65 78 74 46 69 6c 65 41 } //FindNextFileA  1
		$a_80_6 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } //WaitForSingleObject  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=7
 
}