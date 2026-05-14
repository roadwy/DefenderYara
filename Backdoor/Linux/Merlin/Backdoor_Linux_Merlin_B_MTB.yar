
rule Backdoor_Linux_Merlin_B_MTB{
	meta:
		description = "Backdoor:Linux/Merlin.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 74 70 61 75 35 69 61 47 75 4f 2e 28 2a 68 74 74 70 32 43 6c 69 65 6e 74 43 6f 6e 6e 29 2e 50 69 6e 67 } //1 Otpau5iaGuO.(*http2ClientConn).Ping
		$a_01_1 = {48 72 78 36 47 7a 58 44 2e 28 2a 50 69 6e 67 46 72 61 6d 65 29 2e 49 73 41 63 6b } //1 Hrx6GzXD.(*PingFrame).IsAck
		$a_01_2 = {4f 74 70 61 75 35 69 61 47 75 4f 2e 28 2a 68 74 74 70 32 43 6c 69 65 6e 74 43 6f 6e 6e 29 2e 52 65 73 65 72 76 65 4e 65 77 52 65 71 75 65 73 74 } //1 Otpau5iaGuO.(*http2ClientConn).ReserveNewRequest
		$a_01_3 = {4f 74 70 61 75 35 69 61 47 75 4f 2e 28 2a 68 74 74 70 32 54 72 61 6e 73 70 6f 72 74 29 2e 4e 65 77 43 6c 69 65 6e 74 43 6f 6e 6e } //1 Otpau5iaGuO.(*http2Transport).NewClientConn
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}