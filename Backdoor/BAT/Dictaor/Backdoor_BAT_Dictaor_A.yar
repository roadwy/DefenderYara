
rule Backdoor_BAT_Dictaor_A{
	meta:
		description = "Backdoor:BAT/Dictaor.A,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 69 67 73 63 72 65 65 6e 5f } //01 00  bigscreen_
		$a_01_1 = {43 61 6d 65 72 61 73 74 5f } //01 00  Camerast_
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 65 72 78 5f } //01 00  downloaderx_
		$a_01_3 = {66 69 6c 65 75 70 6c 6f 61 64 5f } //01 00  fileupload_
		$a_01_4 = {6b 6c 6f 67 65 5f } //01 00  kloge_
		$a_01_5 = {6f 6e 6c 69 6e 65 6c 6f 67 65 72 5f } //01 00  onlineloger_
		$a_01_6 = {53 68 65 6c 6c 5f } //01 00  Shell_
		$a_01_7 = {73 6d 61 6c 6c 63 72 6e 5f } //01 00  smallcrn_
		$a_01_8 = {46 69 6c 65 6d 61 6e 67 5f } //00 00  Filemang_
		$a_00_9 = {78 e9 00 00 } //05 00 
	condition:
		any of ($a_*)
 
}
rule Backdoor_BAT_Dictaor_A_2{
	meta:
		description = "Backdoor:BAT/Dictaor.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {3c 00 41 00 4e 00 54 00 49 00 5f 00 56 00 45 00 52 00 3e 00 4e 00 6f 00 20 00 61 00 6e 00 74 00 69 00 20 00 76 00 69 00 72 00 75 00 73 00 2e 00 3c 00 2f 00 41 00 4e 00 54 00 49 00 5f 00 56 00 45 00 52 00 3e 00 } //01 00  <ANTI_VER>No anti virus.</ANTI_VER>
		$a_01_1 = {43 00 41 00 4d 00 3a 00 53 00 43 00 52 00 3c 00 } //01 00  CAM:SCR<
		$a_01_2 = {4b 00 49 00 4c 00 4c 00 3c 00 41 00 4c 00 4c 00 2a 00 } //01 00  KILL<ALL*
		$a_01_3 = {6f 00 6e 00 6c 00 6f 00 67 00 3a 00 73 00 63 00 72 00 3d 00 3c 00 73 00 2d 00 73 00 63 00 72 00 3e 00 } //01 00  onlog:scr=<s-scr>
		$a_01_4 = {5c 00 64 00 75 00 6d 00 70 00 73 00 68 00 65 00 6c 00 6c 00 2e 00 73 00 68 00 } //01 00  \dumpshell.sh
		$a_01_5 = {3a 00 44 00 4f 00 57 00 4d 00 3a 00 3a 00 6a 00 6f 00 70 00 3a 00 3a 00 44 00 4f 00 4e 00 45 00 3a 00 } //00 00  :DOWM::jop::DONE:
		$a_00_6 = {5d 04 00 } //00 dc 
	condition:
		any of ($a_*)
 
}