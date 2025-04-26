
rule Trojan_BAT_Glimpse_SA_MTB{
	meta:
		description = "Trojan:BAT/Glimpse.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {73 63 68 65 6d 61 73 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d 2f 77 69 6e 66 78 2f 32 30 30 36 2f 78 61 6d 6c } //1 schemas.microsoft.com/winfx/2006/xaml
		$a_01_1 = {64 6e 73 5f 75 70 6c 6f 61 64 5f 63 6f 6d 6d 61 6e 64 5f 66 69 6c 65 5f 6e 61 6d 65 5f 70 61 74 68 } //1 dns_upload_command_file_name_path
		$a_01_2 = {6e 65 77 50 61 6e 65 6c 2e 65 78 65 } //1 newPanel.exe
		$a_01_3 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //1 DebuggerBrowsableState
		$a_01_4 = {5c 44 65 62 75 67 5c 6e 65 77 50 61 6e 65 6c 2e 70 64 62 } //1 \Debug\newPanel.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}