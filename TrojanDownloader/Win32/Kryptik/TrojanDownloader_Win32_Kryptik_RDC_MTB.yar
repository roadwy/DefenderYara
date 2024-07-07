
rule TrojanDownloader_Win32_Kryptik_RDC_MTB{
	meta:
		description = "TrojanDownloader:Win32/Kryptik.RDC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 71 75 69 72 65 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 } //1 requireAdministrator
		$a_01_1 = {72 65 71 75 65 73 74 65 64 45 78 65 63 75 74 69 6f 6e 4c 65 76 65 6c } //1 requestedExecutionLevel
		$a_03_2 = {d3 c3 0f c9 d2 dd 8b 4d 90 01 01 02 d9 66 90 01 04 3b fc 32 d3 0f 93 c3 90 00 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}