
rule TrojanProxy_Win32_Radds_A{
	meta:
		description = "TrojanProxy:Win32/Radds.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 4d 69 63 72 6f 73 6f 66 74 5f 5f 53 64 6b 5c 6c 69 62 5c 69 6e 63 6c 75 64 65 5c 63 63 31 78 6d 2e 6a 73 } //01 00  \Microsoft__Sdk\lib\include\cc1xm.js
		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5f 5f 53 64 6b 5c 6c 69 62 5c 69 6e 63 6c 75 64 65 5c 69 65 78 70 6c 6f 72 6f 72 2e 65 78 65 } //01 00  \Microsoft__Sdk\lib\include\iexploror.exe
		$a_01_2 = {73 74 61 52 74 20 22 64 64 73 64 73 63 63 73 73 22 } //00 00  staRt "ddsdsccss"
	condition:
		any of ($a_*)
 
}