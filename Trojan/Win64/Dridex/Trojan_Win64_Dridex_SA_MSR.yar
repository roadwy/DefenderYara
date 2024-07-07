
rule Trojan_Win64_Dridex_SA_MSR{
	meta:
		description = "Trojan:Win64/Dridex.SA!MSR,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {61 00 64 00 73 00 31 00 43 00 68 00 72 00 6f 00 6d 00 65 00 42 00 } //1 ads1ChromeB
		$a_01_1 = {43 00 68 00 72 00 6f 00 6d 00 65 00 31 00 37 00 61 00 73 00 6b 00 73 00 5a 00 49 00 72 00 65 00 6d 00 6f 00 76 00 65 00 64 00 } //1 Chrome17asksZIremoved
		$a_01_2 = {4c 6f 63 6b 57 69 6e 64 6f 77 55 70 64 61 74 65 } //1 LockWindowUpdate
		$a_01_3 = {63 00 61 00 63 00 74 00 75 00 73 00 2d 00 72 00 69 00 64 00 64 00 65 00 6e 00 63 00 6f 00 64 00 65 00 } //1 cactus-riddencode
		$a_01_4 = {54 72 61 63 65 4d 6f 6e 6b 65 79 } //1 TraceMonkey
		$a_01_5 = {66 69 74 6f 57 75 73 65 64 43 68 72 6f 6d 65 } //1 fitoWusedChrome
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}