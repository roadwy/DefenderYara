
rule VirTool_Win64_Carseat_A{
	meta:
		description = "VirTool:Win64/Carseat.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 6f 6d 6d 61 6e 64 73 5c 77 69 6e 64 6f 77 73 61 75 74 6f 6c 6f 67 6f 6e 5f 63 6f 6d 6d 61 6e 64 2e 70 79 } //1 commands\windowsautologon_command.py
		$a_01_1 = {5c 73 63 68 65 64 75 6c 65 64 74 61 73 6b 73 5f 63 6f 6d 6d 61 6e 64 2e 70 79 } //1 \scheduledtasks_command.py
		$a_01_2 = {72 64 70 73 61 76 65 64 63 6f 6e 6e 65 63 74 69 6f 6e 73 5f 63 6f 6d 6d 61 6e 64 2e 70 79 } //1 rdpsavedconnections_command.py
		$a_01_3 = {70 72 6f 63 65 73 73 63 72 65 61 74 69 6f 6e 65 76 65 6e 74 73 5f 63 6f 6d 6d 61 6e 64 2e 70 79 } //1 processcreationevents_command.py
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}