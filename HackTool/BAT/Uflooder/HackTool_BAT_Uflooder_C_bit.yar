
rule HackTool_BAT_Uflooder_C_bit{
	meta:
		description = "HackTool:BAT/Uflooder.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 61 00 20 00 70 00 72 00 6f 00 70 00 65 00 72 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 20 00 6d 00 65 00 74 00 68 00 6f 00 64 00 } //01 00  Select a proper attack method
		$a_01_1 = {4c 00 4f 00 49 00 43 00 2e 00 65 00 78 00 65 00 } //01 00  LOIC.exe
		$a_01_2 = {4c 00 6f 00 77 00 20 00 4f 00 72 00 62 00 69 00 74 00 20 00 49 00 6f 00 6e 00 20 00 43 00 61 00 6e 00 6e 00 6f 00 6e 00 } //01 00  Low Orbit Ion Cannon
		$a_01_3 = {54 00 43 00 50 00 2f 00 49 00 50 00 20 00 73 00 74 00 72 00 65 00 73 00 73 00 2d 00 74 00 65 00 73 00 74 00 20 00 74 00 6f 00 6f 00 6c 00 } //00 00  TCP/IP stress-test tool
	condition:
		any of ($a_*)
 
}