
rule Trojan_Win32_RaccoonStealer_D_MTB{
	meta:
		description = "Trojan:Win32/RaccoonStealer.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {55 6d 65 6e 64 6b 61 69 64 77 6b 6f 61 } //1 Umendkaidwkoa
		$a_81_1 = {65 75 69 73 66 64 6a 73 78 61 64 66 64 73 37 } //1 euisfdjsxadfds7
		$a_81_2 = {65 63 72 75 6d 73 61 77 73 } //1 ecrumsaws
		$a_81_3 = {76 73 65 66 6f 63 73 6c 65 64 73 79 } //1 vsefocsledsy
		$a_81_4 = {4a 65 6d 66 73 63 6d 73 65 73 } //1 Jemfscmses
		$a_81_5 = {4e 75 6d 65 72 61 6e 69 75 6d 72 65 6b 78 } //1 Numeraniumrekx
		$a_81_6 = {77 64 33 64 77 65 72 65 77 6f 6c 69 6f 6c 64 73 64 } //1 wd3dwerewolioldsd
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}