
rule Trojan_Win64_Zusy_NZ_MTB{
	meta:
		description = "Trojan:Win64/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 75 73 20 4c 6f 61 64 65 72 2e 70 64 62 } //1 Hus Loader.pdb
		$a_01_1 = {4b 65 79 20 64 6f 65 73 6e 74 20 65 78 69 73 74 20 21 } //1 Key doesnt exist !
		$a_01_2 = {64 73 63 2e 67 67 2f 72 69 76 65 } //1 dsc.gg/rive
		$a_01_3 = {48 75 73 43 6c 61 73 73 } //1 HusClass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win64_Zusy_NZ_MTB_2{
	meta:
		description = "Trojan:Win64/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 74 61 72 74 20 63 6d 64 20 2f 43 } //1 start cmd /C
		$a_01_1 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //1 CreateRemoteThread
		$a_01_2 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //1 ReadProcessMemory
		$a_01_3 = {56 65 72 69 53 69 67 6e 4d 50 4b 49 2d 32 2d 33 39 35 30 } //1 VeriSignMPKI-2-3950
		$a_01_4 = {4f 52 5f 31 50 34 52 50 34 31 } //1 OR_1P4RP41
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_Win64_Zusy_NZ_MTB_3{
	meta:
		description = "Trojan:Win64/Zusy.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {48 69 76 65 4e 69 67 68 74 6d 61 72 65 2e 70 64 62 } //2 HiveNightmare.pdb
		$a_01_1 = {6c 69 73 74 20 73 6e 61 70 73 68 6f 74 73 20 77 69 74 68 20 76 73 73 61 64 6d 69 6e 20 6c 69 73 74 20 73 68 61 64 6f 77 73 } //2 list snapshots with vssadmin list shadows
		$a_01_2 = {70 65 72 6d 69 73 73 69 6f 6e 20 69 73 73 75 65 20 72 61 74 68 65 72 20 74 68 61 6e 20 76 75 6c 6e 65 72 61 62 69 6c 69 74 79 20 69 73 73 75 65 2c 20 6d 61 6b 65 20 73 75 72 65 20 79 6f 75 27 72 65 20 72 75 6e 6e 69 6e 67 20 66 72 6f 6d 20 61 20 66 6f 6c 64 65 72 20 77 68 65 72 65 20 79 6f 75 20 63 61 6e 20 77 72 69 74 65 20 74 6f } //2 permission issue rather than vulnerability issue, make sure you're running from a folder where you can write to
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}