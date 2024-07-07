
rule Misleading_Linux_FastReverseProxy_A_MTB{
	meta:
		description = "Misleading:Linux/FastReverseProxy.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_00_0 = {66 61 74 65 64 69 65 72 2f 66 72 70 2f 6d 6f 64 65 6c 73 2f 6d 73 67 } //1 fatedier/frp/models/msg
		$a_00_1 = {66 61 74 65 64 69 65 72 2f 66 72 70 2f 63 6d 64 2f 66 72 70 63 2f 73 75 62 } //1 fatedier/frp/cmd/frpc/sub
		$a_00_2 = {66 72 70 2f 76 65 6e 64 6f 72 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 73 70 66 31 33 2f 63 6f 62 72 61 } //1 frp/vendor/github.com/spf13/cobra
		$a_00_3 = {66 72 70 2f 76 65 6e 64 6f 72 2f 67 69 74 68 75 62 2e 63 6f 6d 2f 76 61 75 67 68 61 6e 30 2f 67 6f 2d 69 6e 69 } //1 frp/vendor/github.com/vaughan0/go-ini
		$a_00_4 = {2a 63 6f 6e 66 69 67 2e 42 69 6e 64 49 6e 66 6f 43 6f 6e 66 } //1 *config.BindInfoConf
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=3
 
}