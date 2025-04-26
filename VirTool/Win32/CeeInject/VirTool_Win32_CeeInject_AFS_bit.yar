
rule VirTool_Win32_CeeInject_AFS_bit{
	meta:
		description = "VirTool:Win32/CeeInject.AFS!bit,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 64 61 68 6b 53 65 72 76 69 63 65 5c 64 61 68 6b 53 65 72 76 69 63 65 2e 65 78 65 } //1 \dahkService\dahkService.exe
		$a_01_1 = {63 6c 69 65 6e 74 5f 69 64 3d 25 2e 38 78 26 63 6f 6e 6e 65 63 74 65 64 3d 25 64 26 73 65 72 76 65 72 5f 70 6f 72 74 3d 25 64 } //1 client_id=%.8x&connected=%d&server_port=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}