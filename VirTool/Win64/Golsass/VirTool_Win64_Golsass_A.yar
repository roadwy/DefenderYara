
rule VirTool_Win64_Golsass_A{
	meta:
		description = "VirTool:Win64/Golsass.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 61 69 6e 2e 69 6e 73 74 61 6c 6c 53 65 72 76 69 63 65 } //1 main.installService
		$a_01_1 = {73 6d 62 2f 64 63 65 72 70 63 2e 42 69 6e 64 52 65 71 } //1 smb/dcerpc.BindReq
		$a_01_2 = {6d 61 69 6e 2e 63 6c 65 61 6e 75 70 } //1 main.cleanup
		$a_01_3 = {69 63 6d 70 6c 6f 63 61 6c 68 6f 73 74 6c 73 61 73 73 2e 64 6d 70 6c 73 61 73 73 } //1 icmplocalhostlsass.dmplsass
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}