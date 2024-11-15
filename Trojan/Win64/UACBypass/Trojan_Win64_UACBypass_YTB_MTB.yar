
rule Trojan_Win64_UACBypass_YTB_MTB{
	meta:
		description = "Trojan:Win64/UACBypass.YTB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {43 3a 2f 54 65 6d 70 2f 66 69 72 65 64 72 69 6c 6c 2d 6d 61 69 6e 2f 66 69 72 65 64 72 69 6c 6c 2d 6d 61 69 6e 2f 63 6d 64 2f 75 61 63 5f 62 79 70 61 73 73 2f 6d 61 69 6e 2e 67 6f } //1 C:/Temp/firedrill-main/firedrill-main/cmd/uac_bypass/main.go
		$a_81_1 = {70 6b 67 2f 62 65 68 61 76 69 6f 75 72 73 2f 62 79 70 61 73 73 5f 66 6f 64 68 65 6c 70 65 72 } //1 pkg/behaviours/bypass_fodhelper
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}