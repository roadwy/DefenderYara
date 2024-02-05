
rule HackTool_Win32_Mimikatz_SA{
	meta:
		description = "HackTool:Win32/Mimikatz.SA,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 05 00 "
		
	strings :
		$a_80_0 = {6d 69 6d 69 6b 61 74 7a 2e 65 78 65 } //mimikatz.exe  05 00 
		$a_80_1 = {45 78 65 63 75 74 69 6e 67 20 4d 69 6d 69 6b 61 74 7a } //Executing Mimikatz  05 00 
		$a_80_2 = {46 69 6c 65 20 52 65 61 64 79 2c 20 4e 6f 77 20 44 65 6c 69 76 65 72 20 50 61 79 6c 6f 61 64 } //File Ready, Now Deliver Payload  0a 00 
		$a_00_3 = {ba dc 0f fe eb ad be fd ea db ab ef ac e8 ac dc } //01 00 
		$a_00_4 = {5d 04 00 00 70 99 04 80 5c 24 } //00 00 
	condition:
		any of ($a_*)
 
}