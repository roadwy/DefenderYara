
rule Trojan_MacOS_Sliver_D_MTB{
	meta:
		description = "Trojan:MacOS/Sliver.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_00_0 = {73 6c 69 76 65 72 70 62 2e 53 68 65 6c 6c } //1 sliverpb.Shell
		$a_00_1 = {73 6c 69 76 65 72 70 62 2e 42 61 63 6b 64 6f 6f 72 52 65 71 } //1 sliverpb.BackdoorReq
		$a_00_2 = {73 6c 69 76 65 72 70 62 2e 50 72 6f 63 65 73 73 44 75 6d 70 52 65 71 } //1 sliverpb.ProcessDumpReq
		$a_00_3 = {67 69 74 68 75 62 2e 63 6f 6d 2f 62 69 73 68 6f 70 66 6f 78 2f 73 6c 69 76 65 72 2f 69 6d 70 6c 61 6e 74 2f 73 6c 69 76 65 72 2f } //1 github.com/bishopfox/sliver/implant/sliver/
		$a_00_4 = {53 63 72 65 65 6e 73 68 6f 74 52 65 71 } //1 ScreenshotReq
		$a_00_5 = {62 69 73 68 6f 70 66 6f 78 2f 73 6c 69 76 65 72 2f 70 72 6f 74 6f 62 75 66 2f 73 6c 69 76 65 72 70 62 62 2e } //1 bishopfox/sliver/protobuf/sliverpbb.
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=4
 
}