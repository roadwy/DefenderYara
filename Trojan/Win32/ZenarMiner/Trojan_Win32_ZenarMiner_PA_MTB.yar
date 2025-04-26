
rule Trojan_Win32_ZenarMiner_PA_MTB{
	meta:
		description = "Trojan:Win32/ZenarMiner.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 4b 20 74 61 73 6b 6b 69 6c 6c 20 2f 49 4d } //1 /K taskkill /IM
		$a_01_1 = {6d 00 69 00 72 00 6b 00 6f 00 73 00 69 00 72 00 6b 00 6f 00 40 00 70 00 69 00 67 00 6d 00 6f 00 } //1 mirkosirko@pigmo
		$a_01_2 = {69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 } //1 iplogger.org
		$a_01_3 = {5c 5a 65 6e 61 72 2e 70 64 62 } //1 \Zenar.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}