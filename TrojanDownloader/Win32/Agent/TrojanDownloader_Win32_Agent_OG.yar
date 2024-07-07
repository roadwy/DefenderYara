
rule TrojanDownloader_Win32_Agent_OG{
	meta:
		description = "TrojanDownloader:Win32/Agent.OG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6b 73 69 6e 6e 65 2e 63 6f 6d 2f 62 73 33 30 2e 70 68 70 00 3f 72 6e 64 31 3d 25 78 26 72 6e 64 32 3d 25 64 } //1 獫湩敮挮浯戯㍳⸰桰p爿摮㴱砥爦摮㴲搥
		$a_03_1 = {74 14 6a 00 6a 00 68 90 01 04 8d 45 90 01 01 50 6a 00 e8 90 01 01 00 00 00 68 20 4e 00 00 ff 15 90 01 04 b9 01 00 00 00 85 c9 74 0d 68 00 04 00 00 ff 15 90 01 04 eb ea 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}