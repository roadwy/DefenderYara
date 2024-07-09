
rule VirTool_WinNT_Rootkitdrv_GQ{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.GQ,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {3d 00 20 00 80 be 0d 00 00 c0 74 ?? 3d 04 20 00 80 75 } //1
		$a_00_1 = {43 6d 55 6e 52 65 67 69 73 74 65 72 43 61 6c 6c 62 61 63 6b } //1 CmUnRegisterCallback
		$a_00_2 = {49 6f 66 43 6f 6d 70 6c 65 74 65 52 65 71 75 65 73 74 } //1 IofCompleteRequest
		$a_00_3 = {53 00 45 00 52 00 56 00 49 00 43 00 45 00 53 00 5c 00 4d 00 4e 00 4d 00 53 00 52 00 56 00 43 00 } //1 SERVICES\MNMSRVC
		$a_00_4 = {53 00 45 00 52 00 56 00 49 00 43 00 45 00 53 00 5c 00 49 00 4d 00 41 00 50 00 49 00 53 00 45 00 52 00 56 00 49 00 43 00 45 00 } //1 SERVICES\IMAPISERVICE
	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}