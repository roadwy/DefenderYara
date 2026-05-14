
rule Trojan_Linux_ReverseShell_HAB_MTB{
	meta:
		description = "Trojan:Linux/ReverseShell.HAB!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,20 00 20 00 05 00 00 "
		
	strings :
		$a_81_0 = {24 53 74 72 65 61 6d 57 72 69 74 65 72 2e 57 72 69 74 65 28 24 53 74 72 69 6e 67 20 2b 20 27 53 48 45 4c 4c 3e 20 27 29 } //20 $StreamWriter.Write($String + 'SHELL> ')
		$a_81_1 = {66 75 6e 63 74 69 6f 6e 20 57 72 69 74 65 54 6f 53 74 72 65 61 6d 20 28 24 53 74 72 69 6e 67 29 20 7b 5b 62 79 74 65 5b 5d 5d 24 73 63 72 69 70 74 3a 42 75 66 66 65 72 20 3d 20 30 2e 2e 24 54 43 50 43 6c 69 65 6e 74 2e 52 65 63 65 69 76 65 42 75 66 66 65 72 53 69 7a 65 } //5 function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize
		$a_81_2 = {24 63 6c 69 65 6e 74 20 3d 20 4e 65 77 2d 4f 62 6a 65 63 74 20 53 79 73 74 65 6d 2e 4e 65 74 2e 53 6f 63 6b 65 74 73 2e 54 43 50 43 6c 69 65 6e 74 28 27 7b 7b 48 4f 53 54 7d 7d 27 2c 7b 7b 50 4f 52 54 7d 7d 29 } //5 $client = New-Object System.Net.Sockets.TCPClient('{{HOST}}',{{PORT}})
		$a_81_3 = {24 4f 75 74 70 75 74 20 3d 20 74 72 79 20 7b 49 6e 76 6f 6b 65 2d 45 78 70 72 65 73 73 69 6f 6e 20 24 43 6f 6d 6d 61 6e 64 20 32 3e } //1 $Output = try {Invoke-Expression $Command 2>
		$a_81_4 = {4f 75 74 2d 53 74 72 69 6e 67 7d 20 63 61 74 63 68 20 7b 24 5f } //1 Out-String} catch {$_
	condition:
		((#a_81_0  & 1)*20+(#a_81_1  & 1)*5+(#a_81_2  & 1)*5+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=32
 
}