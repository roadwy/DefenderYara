
rule Trojan_Win32_SmbEnum_A_MTB{
	meta:
		description = "Trojan:Win32/SmbEnum.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 6d 62 2f 65 6e 63 6f 64 65 72 2f 65 6e 63 6f 64 65 72 2e 67 6f } //1 smb/encoder/encoder.go
		$a_81_1 = {73 6d 62 2f 72 65 6c 61 79 2e 67 6f } //1 smb/relay.go
		$a_81_2 = {2e 4e 65 74 53 68 61 72 65 } //1 .NetShare
		$a_81_3 = {73 6d 62 2e 28 2a 53 65 73 73 69 6f 6e 29 2e 4e 65 77 43 72 65 61 74 65 52 65 71 } //1 smb.(*Session).NewCreateReq
		$a_81_4 = {67 6f 2d 73 6d 62 2f 73 6d 62 2e 28 2a 43 6f 6e 6e 65 63 74 69 6f 6e 29 2e 73 65 6e 64 } //1 go-smb/smb.(*Connection).send
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}