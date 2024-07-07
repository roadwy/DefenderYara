
rule Misleading_MacOS_FRP_A_MTB{
	meta:
		description = "Misleading:MacOS/FRP.A!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 66 61 74 65 64 69 65 72 2f 66 72 70 2f 63 6d 64 2f 66 72 70 63 2f 6d 61 69 6e 2e 67 6f } //1 /fatedier/frp/cmd/frpc/main.go
		$a_01_1 = {2f 72 65 76 65 72 73 65 70 72 6f 78 79 2e 67 6f } //1 /reverseproxy.go
		$a_01_2 = {72 75 6e 74 69 6d 65 2e 70 65 72 73 69 73 74 65 6e 74 61 6c 6c 6f 63 } //1 runtime.persistentalloc
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}