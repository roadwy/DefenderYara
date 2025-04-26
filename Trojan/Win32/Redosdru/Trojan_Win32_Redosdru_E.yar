
rule Trojan_Win32_Redosdru_E{
	meta:
		description = "Trojan:Win32/Redosdru.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6a 7c 56 e8 ?? ?? ?? 00 83 c4 08 85 c0 74 da } //1
		$a_01_1 = {8b cd 2b cf 8b ee 8a 14 01 80 f2 62 88 10 40 83 ed 01 75 f2 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Redosdru_E_2{
	meta:
		description = "Trojan:Win32/Redosdru.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 3a 5c 6a 6f 62 5c 67 68 30 73 74 5c 52 65 6c 65 61 73 65 5c 4c 6f 61 64 65 72 2e 70 64 62 } //1 e:\job\gh0st\Release\Loader.pdb
		$a_03_1 = {8d 0c ad 00 00 00 00 b8 56 55 55 55 f7 e9 8b 47 04 8b ca c1 e9 1f 8d 54 0a 04 52 6a 08 50 ff 15 ?? ?? 40 00 8b f0 89 47 0c 85 f6 75 08 } //1
		$a_01_2 = {7e 11 8a 14 01 80 ea 08 80 f2 20 88 14 01 41 3b ce 7c ef } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}