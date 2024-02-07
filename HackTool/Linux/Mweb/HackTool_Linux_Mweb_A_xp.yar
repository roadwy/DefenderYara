
rule HackTool_Linux_Mweb_A_xp{
	meta:
		description = "HackTool:Linux/Mweb.A!xp,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 77 65 62 20 73 63 61 6e } //01 00  mweb scan
		$a_01_1 = {6d 73 63 61 6e 6e 69 6e 67 20 66 72 6f 6d 20 25 73 20 28 70 69 64 3a 20 25 64 29 } //01 00  mscanning from %s (pid: %d)
		$a_01_2 = {55 6e 6c 47 20 2d 20 62 61 63 6b 64 30 30 72 } //01 00  UnlG - backd00r
		$a_01_3 = {47 45 54 20 2f 63 67 69 2d 62 69 6e 2f 6d 61 6e 2e 73 68 20 48 54 54 50 2f 31 2e 30 } //00 00  GET /cgi-bin/man.sh HTTP/1.0
	condition:
		any of ($a_*)
 
}