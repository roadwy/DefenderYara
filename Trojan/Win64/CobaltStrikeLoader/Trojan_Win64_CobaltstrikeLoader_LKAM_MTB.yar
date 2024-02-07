
rule Trojan_Win64_CobaltstrikeLoader_LKAM_MTB{
	meta:
		description = "Trojan:Win64/CobaltstrikeLoader.LKAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {31 67 69 74 68 75 62 2e 63 6f 6d 2f 6c 61 72 6b 73 75 69 74 65 2f 6f 61 70 69 2d 73 64 6b 2d 67 6f 2f 76 33 2f 73 65 72 76 69 63 65 2f 69 6d 2f 76 31 } //01 00  1github.com/larksuite/oapi-sdk-go/v3/service/im/v1
		$a_01_1 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6c 61 74 6f 72 74 75 67 61 37 31 2f 47 6f 50 65 4c 6f 61 64 65 72 2f 70 6b 67 2f 70 65 6c 6f 61 64 65 72 } //00 00  github.com/latortuga71/GoPeLoader/pkg/peloader
	condition:
		any of ($a_*)
 
}