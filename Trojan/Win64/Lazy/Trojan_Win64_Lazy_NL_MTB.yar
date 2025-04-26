
rule Trojan_Win64_Lazy_NL_MTB{
	meta:
		description = "Trojan:Win64/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 85 ff 48 0f 44 f8 33 c0 48 83 ff e0 77 18 48 8b 0d ?? ?? ?? ?? 8d 50 08 4c 8b c7 } //2
		$a_03_1 = {75 b7 48 8b 1d ?? ?? ?? ?? 48 8b cb e8 c8 17 ff ff 48 83 25 9c 9e 0e 00 00 48 83 27 ?? c7 05 8a c6 0e 00 01 00 00 00 33 c0 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}
rule Trojan_Win64_Lazy_NL_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 6f 6e 73 6f 6c 65 41 70 70 6c 69 63 61 74 69 6f 6e 32 2e 70 64 62 } //1 ConsoleApplication2.pdb
		$a_01_1 = {64 6f 77 6e 6c 6f 61 64 2f 66 6f 6f 74 62 61 6c 6c 2e 74 78 74 } //1 download/football.txt
		$a_01_2 = {6d 79 73 75 70 65 72 73 74 61 63 6b 6f 76 65 72 66 6c 6f 77 } //1 mysuperstackoverflow
		$a_01_3 = {31 35 36 2e 32 34 35 2e 31 39 2e 31 32 37 } //1 156.245.19.127
		$a_01_4 = {49 6e 74 65 72 6e 65 74 52 65 61 64 46 69 6c 65 } //1 InternetReadFile
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_Lazy_NL_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 69 6e 67 20 73 65 6c 66 } //1 Killing self
		$a_01_1 = {52 65 73 74 61 72 74 69 6e 67 20 73 65 6c 66 } //1 Restarting self
		$a_01_2 = {43 4d 44 20 73 65 73 73 69 6f 6e 20 63 6c 6f 73 65 64 } //1 CMD session closed
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 6c 6f 63 61 6c 61 64 6d 69 6e 5c 44 6f 77 6e 6c 6f 61 64 73 5c 4c 69 6c 69 74 68 2d 6d 61 73 74 65 72 5c 4c 69 6c 69 74 68 2d 6d 61 73 74 65 72 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 4c 69 6c 69 74 68 2e 70 64 62 } //1 C:\Users\localadmin\Downloads\Lilith-master\Lilith-master\x64\Release\Lilith.pdb
		$a_01_4 = {43 4d 44 20 73 65 73 73 69 6f 6e 20 6f 70 65 6e 65 64 } //1 CMD session opened
		$a_01_5 = {58 65 23 76 4c 4c 44 20 50 44 42 } //1 Xe#vLLD PDB
		$a_01_6 = {6c 69 6c 69 74 68 52 45 4c 45 41 53 45 2e 65 78 65 } //1 lilithRELEASE.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}