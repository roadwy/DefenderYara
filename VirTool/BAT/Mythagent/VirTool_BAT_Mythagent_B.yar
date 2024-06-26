
rule VirTool_BAT_Mythagent_B{
	meta:
		description = "VirTool:BAT/Mythagent.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 70 6f 6c 6c 6f 2e 4d 61 6e 61 67 65 6d 65 6e 74 2e 43 32 } //01 00  Apollo.Management.C2
		$a_01_1 = {41 70 6f 6c 6c 6f 2e 50 65 65 72 73 2e 53 4d 42 } //01 00  Apollo.Peers.SMB
		$a_01_2 = {47 65 74 4d 79 74 68 69 63 55 55 49 44 } //01 00  GetMythicUUID
		$a_01_3 = {41 70 6f 6c 6c 6f 2e 50 65 65 72 73 2e 54 43 50 } //01 00  Apollo.Peers.TCP
		$a_01_4 = {6d 79 74 68 69 63 46 69 6c 65 49 64 } //00 00  mythicFileId
	condition:
		any of ($a_*)
 
}
rule VirTool_BAT_Mythagent_B_2{
	meta:
		description = "VirTool:BAT/Mythagent.B,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {4a 00 69 00 74 00 74 00 65 00 72 00 3a 00 20 00 7b 00 } //01 00  Jitter: {
		$a_00_1 = {44 00 6f 00 6d 00 61 00 69 00 6e 00 73 00 3a 00 20 00 7b 00 } //01 00  Domains: {
		$a_00_2 = {50 00 72 00 6f 00 78 00 79 00 20 00 41 00 64 00 64 00 72 00 65 00 73 00 73 00 3a 00 20 00 7b 00 } //01 00  Proxy Address: {
		$a_00_3 = {6b 00 69 00 6c 00 6c 00 5f 00 64 00 61 00 74 00 65 00 } //01 00  kill_date
		$a_00_4 = {68 00 6f 00 73 00 74 00 5f 00 68 00 65 00 61 00 64 00 65 00 72 00 } //01 00  host_header
		$a_00_5 = {4b 69 6c 6c 4a 6f 62 00 } //01 00  楋汬潊b
		$a_00_6 = {47 65 74 4a 6f 62 73 00 } //01 00  敇䩴扯s
		$a_01_7 = {41 00 6d 00 73 00 69 00 53 00 63 00 61 00 6e 00 42 00 75 00 66 00 66 00 65 00 72 00 } //01 00  AmsiScanBuffer
		$a_01_8 = {45 00 74 00 77 00 45 00 76 00 65 00 6e 00 74 00 57 00 72 00 69 00 74 00 65 00 } //00 00  EtwEventWrite
	condition:
		any of ($a_*)
 
}