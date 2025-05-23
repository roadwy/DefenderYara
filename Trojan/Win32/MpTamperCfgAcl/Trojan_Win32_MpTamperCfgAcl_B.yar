
rule Trojan_Win32_MpTamperCfgAcl_B{
	meta:
		description = "Trojan:Win32/MpTamperCfgAcl.B,SIGNATURE_TYPE_CMDHSTR_EXT,46 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 64 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 } //3 software\microsoft\windows defender
		$a_00_1 = {20 00 2d 00 6f 00 6e 00 20 00 } //1  -on 
		$a_00_2 = {20 00 2d 00 6f 00 74 00 20 00 } //1  -ot 
		$a_00_3 = {20 00 72 00 65 00 67 00 20 00 } //1  reg 
		$a_00_4 = {20 00 2d 00 61 00 63 00 74 00 6e 00 20 00 } //1  -actn 
		$a_00_5 = {20 00 73 00 65 00 74 00 6f 00 77 00 6e 00 65 00 72 00 20 00 } //1  setowner 
		$a_00_6 = {20 00 2d 00 6f 00 77 00 6e 00 72 00 20 00 } //1  -ownr 
		$a_00_7 = {20 00 61 00 63 00 65 00 20 00 } //1  ace 
		$a_00_8 = {20 00 2d 00 61 00 63 00 65 00 20 00 } //1  -ace 
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=9
 
}