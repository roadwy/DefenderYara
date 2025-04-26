
rule Trojan_Win32_NfLog_A{
	meta:
		description = "Trojan:Win32/NfLog.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 "
		
	strings :
		$a_80_0 = {4e 66 4c 6f 67 2f 54 54 69 70 2e 61 73 70 } //NfLog/TTip.asp  1
		$a_80_1 = {2f 4e 66 43 6f 6d 6d 61 6e 64 2e 61 73 70 } ///NfCommand.asp  1
		$a_80_2 = {4e 66 53 74 61 72 74 } //NfStart  1
		$a_80_3 = {63 3a 5c 6d 79 66 69 6c 65 2e 64 61 74 } //c:\myfile.dat  1
		$a_80_4 = {4e 66 63 6f 72 65 4f 6b } //NfcoreOk  1
		$a_80_5 = {26 64 74 69 6d 65 3d } //&dtime=  1
		$a_80_6 = {3f 43 6c 69 65 6e 74 49 64 3d } //?ClientId=  1
		$a_80_7 = {4d 79 54 6d 70 46 69 6c 65 2e 44 61 74 } //MyTmpFile.Dat  1
		$a_80_8 = {3f 70 61 72 3d 63 6f 6d 65 64 61 74 61 } //?par=comedata  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1) >=7
 
}