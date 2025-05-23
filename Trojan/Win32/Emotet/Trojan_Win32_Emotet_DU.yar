
rule Trojan_Win32_Emotet_DU{
	meta:
		description = "Trojan:Win32/Emotet.DU,SIGNATURE_TYPE_PEHSTR_EXT,07 00 05 00 07 00 00 "
		
	strings :
		$a_02_0 = {23 00 68 00 65 00 72 00 65 00 48 00 52 00 45 00 54 00 40 00 23 00 68 00 65 00 72 00 77 00 48 00 52 00 45 00 54 00 40 00 23 00 68 00 65 00 72 00 24 00 48 00 52 00 45 00 90 05 40 0d 23 24 40 45 65 48 68 52 72 54 74 77 00 00 90 05 15 03 31 2d 36 } //5
		$a_01_1 = {46 00 31 00 6a 00 35 00 48 00 66 00 71 00 68 00 72 00 51 00 33 00 } //2 F1j5HfqhrQ3
		$a_01_2 = {35 00 73 00 59 00 45 00 49 00 64 00 66 00 6b 00 71 00 67 00 6f 00 } //2 5sYEIdfkqgo
		$a_01_3 = {2e 6a 6e 62 63 66 } //2 .jnbcf
		$a_01_4 = {43 00 61 00 6e 00 61 00 64 00 69 00 61 00 6e 00 20 00 4d 00 } //2 Canadian M
		$a_01_5 = {4e 00 65 00 72 00 6f 00 20 00 42 00 75 00 72 00 6e 00 69 00 6e 00 67 00 20 00 52 00 4f 00 4d 00 } //1 Nero Burning ROM
		$a_01_6 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 } //1 Microsoft Corp
	condition:
		((#a_02_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=5
 
}