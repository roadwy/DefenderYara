
rule VirTool_WinNT_Rootkitdrv_KO{
	meta:
		description = "VirTool:WinNT/Rootkitdrv.KO,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 62 52 65 66 65 72 65 6e 63 65 4f 62 6a 65 63 74 42 79 4e 61 6d 65 } //1 ObReferenceObjectByName
		$a_01_1 = {4e 64 69 73 52 65 67 69 73 74 65 72 50 72 6f 74 6f 63 6f 6c } //1 NdisRegisterProtocol
		$a_00_2 = {5c 00 44 00 72 00 69 00 76 00 65 00 72 00 5c 00 54 00 63 00 70 00 69 00 70 00 } //1 \Driver\Tcpip
		$a_00_3 = {5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 49 00 70 00 66 00 69 00 6c 00 74 00 65 00 72 00 64 00 72 00 69 00 76 00 65 00 72 00 } //1 \Device\Ipfilterdriver
		$a_03_4 = {80 39 e8 75 90 01 01 8b 51 01 8d 54 0a 05 81 3a 58 83 c0 03 75 90 01 01 8b 51 08 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}