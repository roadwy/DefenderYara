
rule HackTool_Win32_Wirekeyview_dha{
	meta:
		description = "HackTool:Win32/Wirekeyview!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 05 00 00 "
		
	strings :
		$a_01_0 = {57 69 72 65 6c 65 73 73 4b 65 79 56 69 65 77 } //1 WirelessKeyView
		$a_01_1 = {50 6f 6c 69 63 79 5c 50 6f 6c 53 65 63 72 65 74 45 6e 63 72 79 70 74 69 6f 6e 4b 65 79 } //1 Policy\PolSecretEncryptionKey
		$a_01_2 = {4d 69 63 72 6f 73 6f 66 74 5c 57 5a 43 53 56 43 5c 50 61 72 61 6d 65 74 65 72 73 5c 49 6e 74 65 72 66 61 63 65 73 } //1 Microsoft\WZCSVC\Parameters\Interfaces
		$a_01_3 = {41 70 70 44 61 74 61 5c 52 6f 61 6d 69 6e 67 5c 4d 69 63 72 6f 73 6f 66 74 5c 50 72 6f 74 65 63 74 } //1 AppData\Roaming\Microsoft\Protect
		$a_01_4 = {22 25 73 22 20 2f 47 65 74 4b 65 79 73 20 25 73 } //1 "%s" /GetKeys %s
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=100
 
}