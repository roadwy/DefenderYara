
rule HackTool_Win32_Zeloxat_A{
	meta:
		description = "HackTool:Win32/Zeloxat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {2d 6c 69 73 74 65 6e 20 70 6f 72 74 31 20 70 6f 72 74 32 } //01 00  -listen port1 port2
		$a_01_1 = {2d 73 6c 61 76 65 20 6c 6f 63 61 6c 70 6f 72 74 20 72 65 6d 6f 74 65 69 70 20 72 65 6d 6f 74 65 70 6f 72 74 } //01 00  -slave localport remoteip remoteport
		$a_01_2 = {2d 69 6e 6a 65 63 74 20 6c 6f 63 61 6c 70 6f 72 74 20 72 65 6d 6f 74 65 69 70 20 72 65 6d 6f 74 65 70 6f 72 74 20 5b 2d 70 61 74 68 20 65 78 65 70 61 74 68 5d } //01 00  -inject localport remoteip remoteport [-path exepath]
		$a_01_3 = {77 61 74 69 6e 67 20 6f 6e 20 70 6f 72 74 20 25 64 2e 2e 2e } //00 00  wating on port %d...
	condition:
		any of ($a_*)
 
}