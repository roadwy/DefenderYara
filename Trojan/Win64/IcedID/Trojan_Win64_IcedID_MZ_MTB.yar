
rule Trojan_Win64_IcedID_MZ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {8a 09 88 08 eb 18 48 ff c0 48 89 44 24 10 eb 5b eb 6e 48 8b 44 24 08 48 8b 4c 24 10 eb e2 48 8b 44 24 08 48 ff c0 eb } //10
		$a_01_1 = {4e 6a 61 73 64 6b 61 73 6a 64 } //5 Njasdkasjd
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*5) >=15
 
}
rule Trojan_Win64_IcedID_MZ_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } //10 RunObject
		$a_01_1 = {62 38 4a 7a 33 2e 64 6c 6c } //1 b8Jz3.dll
		$a_01_2 = {42 53 51 58 4c 62 64 61 } //1 BSQXLbda
		$a_01_3 = {47 72 32 34 47 61 66 4f 42 } //1 Gr24GafOB
		$a_01_4 = {50 6c 4b 56 78 63 58 35 } //1 PlKVxcX5
		$a_01_5 = {56 63 42 6e 6e 34 6b 39 } //1 VcBnn4k9
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}
rule Trojan_Win64_IcedID_MZ_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.MZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,11 00 11 00 08 00 00 "
		
	strings :
		$a_01_0 = {42 54 54 61 6d 48 6f 2e 64 6c 6c } //10 BTTamHo.dll
		$a_01_1 = {68 71 6c 69 74 65 33 5f 61 67 67 72 65 67 61 74 65 5f 63 6f 6e 74 65 78 74 } //1 hqlite3_aggregate_context
		$a_01_2 = {68 71 6c 69 74 65 33 5f 61 67 67 72 65 67 61 74 65 5f 63 6f 75 6e 74 } //1 hqlite3_aggregate_count
		$a_01_3 = {68 71 6c 69 74 65 33 5f 61 75 74 6f 5f 65 78 74 65 6e 73 69 6f 6e } //1 hqlite3_auto_extension
		$a_01_4 = {68 71 6c 69 74 65 33 5f 62 61 63 6b 75 70 5f 66 69 6e 69 73 68 } //1 hqlite3_backup_finish
		$a_01_5 = {68 71 6c 69 74 65 33 5f 62 61 63 6b 75 70 5f 69 6e 69 74 } //1 hqlite3_backup_init
		$a_01_6 = {47 65 74 44 69 73 6b 46 72 65 65 53 70 61 63 65 57 } //1 GetDiskFreeSpaceW
		$a_01_7 = {4c 6f 63 6b 46 69 6c 65 } //1 LockFile
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=17
 
}