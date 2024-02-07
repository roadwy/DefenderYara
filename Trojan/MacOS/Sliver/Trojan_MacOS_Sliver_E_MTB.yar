
rule Trojan_MacOS_Sliver_E_MTB{
	meta:
		description = "Trojan:MacOS/Sliver.E!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 73 68 6f 70 66 6f 78 2f 73 6c 69 76 65 72 2f 70 72 6f 74 6f 62 75 66 2f 73 6c 69 76 65 72 70 62 62 } //01 00  bishopfox/sliver/protobuf/sliverpbb
		$a_01_1 = {73 6c 69 76 65 72 70 62 2e 50 69 76 6f 74 4c 69 73 74 65 6e 65 72 } //01 00  sliverpb.PivotListener
		$a_01_2 = {53 63 72 65 65 6e 73 68 6f 74 52 65 71 } //01 00  ScreenshotReq
		$a_01_3 = {53 53 48 43 6f 6d 6d 61 6e 64 52 65 71 } //01 00  SSHCommandReq
		$a_01_4 = {42 61 63 6b 64 6f 6f 72 52 65 71 } //01 00  BackdoorReq
		$a_01_5 = {73 6c 69 76 65 72 70 62 2e 52 65 67 69 73 74 65 72 52 } //00 00  sliverpb.RegisterR
	condition:
		any of ($a_*)
 
}