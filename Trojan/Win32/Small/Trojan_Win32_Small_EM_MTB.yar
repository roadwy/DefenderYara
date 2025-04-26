
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