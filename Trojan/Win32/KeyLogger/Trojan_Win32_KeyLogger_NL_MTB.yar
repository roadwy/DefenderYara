
rule Trojan_Win32_KeyLogger_NL_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.NL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 08 00 00 "
		
	strings :
		$a_01_0 = {4c 61 7a 4c 6f 67 67 65 72 } //3 LazLogger
		$a_01_1 = {4b 65 65 70 43 6f 6e 6e 65 63 74 69 6f 6e 54 44 59 } //2 KeepConnectionTDY
		$a_01_2 = {44 45 53 5f 65 63 62 5f 65 6e 63 72 79 70 74 } //1 DES_ecb_encrypt
		$a_01_3 = {66 70 6f 70 65 6e 73 73 6c 2e 73 65 72 72 66 61 69 6c 65 64 74 6f 63 72 65 61 74 65 73 73 6c } //1 fpopenssl.serrfailedtocreatessl
		$a_01_4 = {5c 67 72 62 2e 64 61 6e } //1 \grb.dan
		$a_01_5 = {6f 62 65 61 70 70 2e 65 78 65 } //1 obeapp.exe
		$a_01_6 = {50 72 65 73 73 20 41 62 6f 72 74 20 74 6f 20 6b 69 6c 6c 20 74 68 65 20 70 72 6f 67 72 61 6d 2e } //1 Press Abort to kill the program.
		$a_01_7 = {4b 41 42 78 36 34 } //1 KABx64
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=11
 
}