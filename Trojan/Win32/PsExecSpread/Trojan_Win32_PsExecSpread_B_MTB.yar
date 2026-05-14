
rule Trojan_Win32_PsExecSpread_B_MTB{
	meta:
		description = "Trojan:Win32/PsExecSpread.B!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {2d 00 61 00 63 00 63 00 65 00 70 00 74 00 65 00 75 00 6c 00 61 00 20 00 5c 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 2e 00 [0-06] 20 00 2d 00 63 00 20 00 [0-50] 2e 00 65 00 78 00 65 00 } //1
		$a_00_1 = {2d 00 2d 00 73 00 70 00 72 00 65 00 61 00 64 00 } //1 --spread
		$a_00_2 = {2d 00 2d 00 70 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 } //1 --password
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}