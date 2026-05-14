
rule Trojan_Win32_Small_EM_MTB{
	meta:
		description = "Trojan:Win32/Small.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {83 c6 04 66 ba 31 df 39 fe 7c ef 66 bf ac e1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win32_Small_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Small.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {61 66 66 2e 72 6b 72 75 72 65 69 6e } //1 aff.rkrurein
		$a_81_1 = {2d 4c 49 42 47 43 43 57 33 32 2d 45 48 2d } //1 -LIBGCCW32-EH-
		$a_81_2 = {73 6d 6e 73 73 2e 65 78 65 } //1 smnss.exe
		$a_81_3 = {66 7a 61 66 66 2e 72 6b 72 } //1 fzaff.rkr
		$a_81_4 = {66 75 72 65 69 6e 61 66 2e 71 79 79 } //1 fureinaf.qyy
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_Small_EM_MTB_3{
	meta:
		description = "Trojan:Win32/Small.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4c 01 03 00 a0 43 e2 34 } //1
		$a_81_1 = {55 6e 6d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 UnmapViewOfFile
		$a_81_2 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } //1 MapViewOfFile
		$a_81_3 = {4f 70 65 6e 46 69 6c 65 4d 61 70 70 69 6e 67 41 } //1 OpenFileMappingA
		$a_81_4 = {44 52 41 4d 4d 41 50 } //1 DRAMMAP
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}