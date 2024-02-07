
rule Backdoor_O97M_JumplumpDropper_A_dha{
	meta:
		description = "Backdoor:O97M/JumplumpDropper.A!dha,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {74 65 6c 6c 69 6e 67 20 68 65 72 20 61 62 6f 75 74 20 6d 65 64 69 63 69 6e 65 73 20 66 6f 72 20 67 65 74 74 69 6e 67 20 63 68 69 6c 64 72 65 6e 2c 20 62 79 20 74 61 6c 6b 69 6e 67 20 74 6f 20 68 65 72 } //01 00  telling her about medicines for getting children, by talking to her
		$a_00_1 = {57 68 69 63 68 65 76 65 72 20 6f 66 20 74 68 65 20 61 62 6f 76 65 20 63 61 75 73 65 73 20 61 20 6d 61 6e 20 6d 61 79 20 64 65 74 65 63 74 2c 20 68 65 20 73 68 6f 75 6c 64 20 65 6e 64 65 61 76 6f 75 72 20 74 6f } //01 00  Whichever of the above causes a man may detect, he should endeavour to
		$a_00_2 = {49 6e 20 74 68 65 20 73 61 6d 65 20 77 61 79 20 61 20 67 69 72 6c 20 77 68 6f 20 69 73 20 63 61 6c 6c 65 64 20 62 79 20 74 68 65 20 6e 61 6d 65 20 6f 66 20 6f 6e 65 20 6f 66 20 74 68 65 } //01 00  In the same way a girl who is called by the name of one of the
		$a_00_3 = {70 72 6f 70 65 72 74 79 20 69 6e 66 72 69 6e 67 65 6d 65 6e 74 2c 20 61 20 64 65 66 65 63 74 69 76 65 20 6f 72 20 64 61 6d 61 67 65 64 20 64 69 73 6b 20 6f 72 20 6f 74 68 65 72 20 6d 65 64 69 75 6d 2c 20 61 } //01 00  property infringement, a defective or damaged disk or other medium, a
		$a_00_4 = {63 6f 72 72 75 70 74 20 64 61 74 61 2c 20 74 72 61 6e 73 63 72 69 70 74 69 6f 6e 20 65 72 72 6f 72 73 2c 20 61 20 63 6f 70 79 72 69 67 68 74 20 6f 72 20 6f 74 68 65 72 20 69 6e 74 65 6c 6c 65 63 74 75 61 6c } //00 00  corrupt data, transcription errors, a copyright or other intellectual
	condition:
		any of ($a_*)
 
}