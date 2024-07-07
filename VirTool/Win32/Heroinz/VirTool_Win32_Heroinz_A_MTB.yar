
rule VirTool_Win32_Heroinz_A_MTB{
	meta:
		description = "VirTool:Win32/Heroinz.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {68 65 72 6f 69 6e 6e 5f 63 6c 69 65 6e 74 3a 3a 6d 6f 64 75 6c 65 3a 3a 66 74 70 } //1 heroinn_client::module::ftp
		$a_81_1 = {68 65 72 6f 69 6e 6e 5f 63 6c 69 65 6e 74 3a 3a 63 6f 6e 66 69 67 68 65 72 6f 69 6e 6e 5f 63 6c 69 65 6e 74 5c 73 72 63 } //1 heroinn_client::configheroinn_client\src
		$a_81_2 = {68 65 72 6f 69 6e 6e 5f 75 74 69 6c 5c 73 72 63 5c 70 61 63 6b 65 74 } //1 heroinn_util\src\packet
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}