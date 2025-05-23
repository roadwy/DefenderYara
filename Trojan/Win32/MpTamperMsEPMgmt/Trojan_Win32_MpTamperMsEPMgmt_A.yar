
rule Trojan_Win32_MpTamperMsEPMgmt_A{
	meta:
		description = "Trojan:Win32/MpTamperMsEPMgmt.A,SIGNATURE_TYPE_CMDHSTR_EXT,37 00 0a 00 08 00 00 "
		
	strings :
		$a_00_0 = {5c 00 6d 00 73 00 69 00 65 00 78 00 65 00 63 00 2e 00 65 00 78 00 65 00 } //3 \msiexec.exe
		$a_00_1 = {7b 00 39 00 34 00 32 00 65 00 61 00 31 00 65 00 63 00 2d 00 37 00 33 00 39 00 31 00 2d 00 34 00 61 00 62 00 64 00 2d 00 39 00 35 00 32 00 34 00 2d 00 33 00 38 00 38 00 62 00 63 00 32 00 64 00 37 00 30 00 36 00 37 00 33 00 7d 00 } //3 {942ea1ec-7391-4abd-9524-388bc2d70673}
		$a_00_2 = {2f 00 78 00 } //2 /x
		$a_00_3 = {2f 00 75 00 6e 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 } //2 /uninstall
		$a_00_4 = {2f 00 71 00 75 00 69 00 65 00 74 00 } //1 /quiet
		$a_00_5 = {2f 00 71 00 6e 00 } //1 /qn
		$a_00_6 = {6e 00 6f 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //1 norestart
		$a_00_7 = {66 00 6f 00 72 00 63 00 65 00 72 00 65 00 73 00 74 00 61 00 72 00 74 00 } //1 forcerestart
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*2+(#a_00_3  & 1)*2+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=10
 
}