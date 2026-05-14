
rule HackTool_Win64_Mimikatz_AMTB{
	meta:
		description = "HackTool:Win64/Mimikatz!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {78 36 34 2f 6d 69 6d 69 6b 61 74 7a 2e 65 78 65 } //x64/mimikatz.exe  4
		$a_80_1 = {45 78 65 63 75 74 69 6e 67 20 4d 69 6d 69 6b 61 74 7a } //Executing Mimikatz  4
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*4) >=4
 
}