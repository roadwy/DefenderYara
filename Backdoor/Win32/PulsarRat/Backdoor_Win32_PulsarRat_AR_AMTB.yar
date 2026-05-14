
rule Backdoor_Win32_PulsarRat_AR_AMTB{
	meta:
		description = "Backdoor:Win32/PulsarRat.AR!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_80_0 = {50 75 6c 73 61 72 2e 43 6f 6d 6d 6f 6e 2e 4d 65 73 73 61 67 65 73 2e 4d 6f 6e 69 74 6f 72 69 6e 67 2e 43 6c 69 70 62 6f 61 72 64 } //Pulsar.Common.Messages.Monitoring.Clipboard  1
		$a_80_1 = {50 75 6c 73 61 72 2e 43 6f 6d 6d 6f 6e 2e 4d 65 73 73 61 67 65 73 2e 41 64 6d 69 6e 69 73 74 72 61 74 69 6f 6e 2e 52 65 6d 6f 74 65 53 68 65 6c 6c } //Pulsar.Common.Messages.Administration.RemoteShell  1
		$a_80_2 = {50 75 6c 73 61 72 2e 43 6f 6d 6d 6f 6e 2e 4d 65 73 73 61 67 65 73 2e 4d 6f 6e 69 74 6f 72 69 6e 67 2e 4b 65 79 4c 6f 67 67 65 72 } //Pulsar.Common.Messages.Monitoring.KeyLogger  1
		$a_80_3 = {50 75 6c 73 61 72 2e 43 6f 6d 6d 6f 6e 2e 4d 65 73 73 61 67 65 73 2e 4d 6f 6e 69 74 6f 72 69 6e 67 2e 50 61 73 73 77 6f 72 64 73 } //Pulsar.Common.Messages.Monitoring.Passwords  1
		$a_80_4 = {47 65 74 4b 65 79 6c 6f 67 67 65 72 4c 6f 67 73 44 69 72 65 63 74 6f 72 79 } //GetKeyloggerLogsDirectory  1
		$a_80_5 = {73 65 74 5f 46 61 6b 65 41 70 70 44 61 74 61 } //set_FakeAppData  1
		$a_80_6 = {49 4b 65 79 62 6f 61 72 64 4d 6f 75 73 65 45 76 65 6e 74 73 } //IKeyboardMouseEvents  1
		$a_80_7 = {5f 73 63 72 65 65 6e 43 61 70 74 75 72 65 } //_screenCapture  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1) >=8
 
}