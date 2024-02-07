
rule Trojan_BAT_AgentTesla_PAB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 65 74 5f 43 68 65 63 6b 46 6f 72 49 6c 6c 65 67 61 6c 43 72 6f 73 73 54 68 72 65 61 64 43 61 6c 6c 73 } //01 00  set_CheckForIllegalCrossThreadCalls
		$a_01_1 = {44 73 6b 45 78 70 6c 6f 72 65 72 2e 45 74 63 68 65 72 2e 72 65 73 6f 75 72 63 65 73 } //01 00  DskExplorer.Etcher.resources
		$a_01_2 = {53 68 75 74 64 6f 77 6e 45 76 65 6e 74 48 61 6e 64 6c 65 72 } //01 00  ShutdownEventHandler
		$a_01_3 = {4e 65 74 77 6f 72 6b 43 72 65 64 65 6e 74 69 61 6c } //01 00  NetworkCredential
		$a_01_4 = {46 69 6c 65 53 79 73 74 65 6d 50 72 6f 78 79 } //01 00  FileSystemProxy
		$a_01_5 = {43 6c 69 70 62 6f 61 72 64 50 72 6f 78 79 } //01 00  ClipboardProxy
		$a_01_6 = {46 69 6c 65 53 79 73 74 65 6d 49 6e 66 6f } //01 00  FileSystemInfo
		$a_01_7 = {46 74 70 57 65 62 52 65 73 70 6f 6e 73 65 } //01 00  FtpWebResponse
		$a_01_8 = {67 65 74 5f 57 68 69 74 65 53 6d 6f 6b 65 } //01 00  get_WhiteSmoke
		$a_01_9 = {67 65 74 5f 43 6c 69 70 62 6f 61 72 64 } //01 00  get_Clipboard
		$a_01_10 = {49 43 72 65 64 65 6e 74 69 61 6c 73 } //01 00  ICredentials
		$a_01_11 = {47 65 74 54 69 63 6b 43 6f 75 6e 74 } //01 00  GetTickCount
		$a_01_12 = {54 63 70 4c 69 73 74 65 6e 65 72 } //00 00  TcpListener
	condition:
		any of ($a_*)
 
}