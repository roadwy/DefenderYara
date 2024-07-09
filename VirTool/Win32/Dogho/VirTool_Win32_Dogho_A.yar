
rule VirTool_Win32_Dogho_A{
	meta:
		description = "VirTool:Win32/Dogho.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {2f 67 6f 44 6f 48 2f 6d 61 69 6e 2e 67 6f } //1 /goDoH/main.go
		$a_00_1 = {2f 67 6f 44 6f 48 2f 63 6d 64 2f 63 32 2e 67 6f } //1 /goDoH/cmd/c2.go
		$a_01_2 = {2f 73 65 6e 73 65 70 6f 73 74 2f 67 6f 64 6f 68 2f 63 6d 64 2e 65 78 65 63 75 74 65 43 6f 6d 6d 61 6e 64 } //1 /sensepost/godoh/cmd.executeCommand
		$a_01_3 = {2f 67 6f 64 6f 68 2f 64 6e 73 73 65 72 76 65 72 2e 28 2a 48 61 6e 64 6c 65 72 29 2e 53 65 72 76 65 44 4e 53 } //1 /godoh/dnsserver.(*Handler).ServeDNS
		$a_01_4 = {2f 67 6f 64 6f 68 2f 64 6e 73 63 6c 69 65 6e 74 2e 28 2a 52 61 77 44 4e 53 29 2e 4c 6f 6f 6b 75 70 } //1 /godoh/dnsclient.(*RawDNS).Lookup
		$a_03_5 = {2f 67 6f 64 6f 68 2f [0-08] 2e 44 65 63 72 79 70 74 } //1
		$a_01_6 = {2f 67 6f 64 6f 68 2f 70 72 6f 74 6f 63 6f 6c 2e 28 2a 43 6f 6d 6d 61 6e 64 29 2e 47 65 74 4f 75 74 67 6f 69 6e 67 } //1 /godoh/protocol.(*Command).GetOutgoing
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}