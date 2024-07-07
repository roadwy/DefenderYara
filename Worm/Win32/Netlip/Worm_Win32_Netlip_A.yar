
rule Worm_Win32_Netlip_A{
	meta:
		description = "Worm:Win32/Netlip.A,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_02_0 = {43 3a 5c 43 4f 4e 46 49 47 2e 5f 90 01 01 5f 90 00 } //10
		$a_00_1 = {45 73 63 72 69 74 6f 72 69 6f 5c 50 55 42 4c 49 4e 65 74 2e 45 58 45 } //10 Escritorio\PUBLINet.EXE
		$a_00_2 = {53 75 62 6a 65 63 74 3a 20 50 55 42 4c 49 4e 65 74 } //1 Subject: PUBLINet
		$a_00_3 = {52 43 50 54 20 54 4f 3a 20 3c 73 69 63 6f 6d 5f } //1 RCPT TO: <sicom_
		$a_00_4 = {50 00 55 00 42 00 4c 00 49 00 43 00 49 00 44 00 41 00 44 00 20 00 45 00 4c 00 45 00 43 00 54 00 52 00 4f 00 4e 00 49 00 43 00 41 00 } //1 PUBLICIDAD ELECTRONICA
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=22
 
}