
rule VirTool_Win64_Soushelesz_A_MTB{
	meta:
		description = "VirTool:Win64/Soushelesz.A!MTB,SIGNATURE_TYPE_PEHSTR,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 62 75 69 6c 64 70 6c 61 79 6c 69 73 74 } //01 00  .buildplaylist
		$a_01_1 = {2e 65 6e 63 6f 64 65 43 6f 6d 6d 61 6e 64 } //01 00  .encodeCommand
		$a_01_2 = {67 69 74 68 75 62 2e 63 6f 6d 2f 7a 6d 62 33 2f 73 70 6f 74 69 66 79 } //01 00  github.com/zmb3/spotify
		$a_01_3 = {2e 73 6f 63 6b 73 41 75 74 68 4d 65 74 68 6f 64 } //01 00  .socksAuthMethod
		$a_01_4 = {6e 65 74 2f 68 74 74 70 2e 70 65 72 73 69 73 74 43 6f 6e 6e 57 72 69 74 65 72 2e 57 72 69 74 65 } //01 00  net/http.persistConnWriter.Write
		$a_01_5 = {41 64 64 43 6f 6e 6e } //01 00  AddConn
		$a_01_6 = {52 65 6d 6f 74 65 41 64 64 72 } //01 00  RemoteAddr
		$a_01_7 = {41 64 64 54 72 61 63 6b 73 54 6f 50 6c 61 79 6c 69 73 74 } //00 00  AddTracksToPlaylist
	condition:
		any of ($a_*)
 
}