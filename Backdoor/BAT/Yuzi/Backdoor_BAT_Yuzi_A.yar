
rule Backdoor_BAT_Yuzi_A{
	meta:
		description = "Backdoor:BAT/Yuzi.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {5c 59 6f 6f 7a 79 53 65 72 76 65 72 2e 70 64 62 00 } //1
		$a_01_1 = {59 00 6f 00 6f 00 7a 00 79 00 53 00 65 00 72 00 76 00 65 00 72 00 } //1 YoozyServer
		$a_01_2 = {6e 00 65 00 74 00 63 00 6c 00 5f 00 65 00 6e 00 64 00 } //1 netcl_end
		$a_01_3 = {32 00 38 00 31 00 33 00 37 00 } //1 28137
		$a_01_4 = {73 00 63 00 72 00 65 00 65 00 6e 00 73 00 68 00 6f 00 74 00 } //1 screenshot
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}