
rule Trojan_BAT_Atraps_PGA_MTB{
	meta:
		description = "Trojan:BAT/Atraps.PGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 39 ae 00 00 00 06 6f ?? 00 00 0a 0b 16 0c 38 97 00 00 00 07 08 9a 0d 06 09 6f ?? 00 00 0a 25 2d 04 26 14 2b 05 } //5
		$a_01_1 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //3 WriteProcessMemory
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 53 74 72 69 6e 67 } //2 DownloadString
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2) >=10
 
}