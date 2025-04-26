
rule Misleading_Linux_Chisel_B_MTB{
	meta:
		description = "Misleading:Linux/Chisel.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 65 74 73 45 6e 63 72 79 70 74 2e 66 75 6e 63 31 } //2 LetsEncrypt.func1
		$a_01_1 = {4e 65 77 43 42 43 45 6e 63 72 79 70 74 65 72 } //1 NewCBCEncrypter
		$a_01_2 = {63 68 69 73 65 6c 2f 73 65 72 76 65 72 2e 4e 65 77 53 65 72 76 65 72 } //1 chisel/server.NewServer
		$a_00_3 = {6d 61 6e 2d 69 6e 2d 74 68 65 2d 6d 69 64 64 6c 65 20 61 74 74 61 63 6b 73 } //1 man-in-the-middle attacks
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}