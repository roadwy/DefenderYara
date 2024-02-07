
rule HackTool_Win32_Dnscat_A{
	meta:
		description = "HackTool:Win32/Dnscat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4f 4d 4d 41 4e 44 5f 45 58 45 43 20 5b 72 65 71 75 65 73 74 5d 20 3a 3a 20 72 65 71 75 65 73 74 5f 69 64 3a 20 30 78 25 30 34 78 20 3a 3a 20 6e 61 6d 65 3a 20 25 73 20 3a 3a 20 63 6f 6d 6d 61 6e 64 3a 20 25 73 } //01 00  COMMAND_EXEC [request] :: request_id: 0x%04x :: name: %s :: command: %s
		$a_01_1 = {54 55 4e 4e 45 4c 5f 44 41 54 41 20 5b 72 65 71 75 65 73 74 5d 20 3a 3a 20 72 65 71 75 65 73 74 5f 69 64 20 30 78 25 30 34 78 20 3a 3a 20 74 75 6e 6e 65 6c 5f 69 64 20 25 64 } //01 00  TUNNEL_DATA [request] :: request_id 0x%04x :: tunnel_id %d
		$a_01_2 = {53 6f 70 68 69 63 } //01 00  Sophic
		$a_00_3 = {64 6e 73 63 61 74 32 2e 70 64 62 } //00 00  dnscat2.pdb
	condition:
		any of ($a_*)
 
}