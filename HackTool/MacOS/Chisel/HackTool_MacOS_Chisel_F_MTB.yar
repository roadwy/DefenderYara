
rule HackTool_MacOS_Chisel_F_MTB{
	meta:
		description = "HackTool:MacOS/Chisel.F!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 68 69 73 65 6c 2d 76 33 30 2e } //1 chisel-v30.
		$a_01_1 = {6a 70 69 6c 6c 6f 72 61 2f 63 68 69 73 65 6c 2f 73 68 61 72 65 2f 74 75 6e 6e 65 6c } //1 jpillora/chisel/share/tunnel
		$a_01_2 = {63 68 69 73 65 6c 2f 73 68 61 72 65 2f 63 63 72 79 70 74 6f 2e 46 69 6e 67 65 72 70 72 69 6e 74 4b 65 79 } //1 chisel/share/ccrypto.FingerprintKey
		$a_01_3 = {63 6c 69 65 6e 74 2e 4e 65 77 43 6c 69 65 6e 74 2e 50 61 73 73 77 6f 72 64 2e 66 75 6e 63 31 } //1 client.NewClient.Password.func1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}