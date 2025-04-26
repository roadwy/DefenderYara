
rule Spyware_Win32_Conducent{
	meta:
		description = "Spyware:Win32/Conducent,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 69 6d 65 53 69 6e 6b 20 4b 69 6c 6c 20 41 64 20 43 6c 69 65 6e 74 } //4 TimeSink Kill Ad Client
		$a_01_1 = {54 53 5f 4d 67 6d 74 47 65 74 41 64 43 6c 69 63 6b 54 68 72 6f 75 67 68 55 52 4c } //2 TS_MgmtGetAdClickThroughURL
		$a_01_2 = {43 00 6f 00 6e 00 64 00 75 00 63 00 65 00 6e 00 74 00 20 00 41 00 64 00 47 00 61 00 74 00 65 00 77 00 61 00 79 00 } //3 Conducent AdGateway
		$a_01_3 = {43 00 6f 00 6e 00 64 00 75 00 63 00 65 00 6e 00 74 00 20 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 2c 00 20 00 49 00 6e 00 63 00 2e 00 } //2 Conducent Technologies, Inc.
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*2+(#a_01_2  & 1)*3+(#a_01_3  & 1)*2) >=11
 
}