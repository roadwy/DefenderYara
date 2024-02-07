
rule HackTool_Win64_FakeRclone_A{
	meta:
		description = "HackTool:Win64/FakeRclone.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 6f 20 72 65 66 72 65 73 68 20 74 6f 6b 65 6e 20 66 6f 75 6e 64 20 2d 20 72 75 6e 20 60 72 63 6c 6f 6e 65 20 63 6f 6e 66 69 67 20 72 65 63 6f 6e 6e 65 63 74 60 6f 61 75 74 68 32 2f 67 6f 6f 67 6c 65 3a } //00 00  no refresh token found - run `rclone config reconnect`oauth2/google:
	condition:
		any of ($a_*)
 
}