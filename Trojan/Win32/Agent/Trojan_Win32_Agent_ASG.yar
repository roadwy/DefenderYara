
rule Trojan_Win32_Agent_ASG{
	meta:
		description = "Trojan:Win32/Agent.ASG,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 0d 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 64 72 69 76 65 72 73 5c 76 6d 6d 6f 75 73 65 2e 73 79 73 } //01 00  \drivers\vmmouse.sys
		$a_01_1 = {20 21 2e 5c 73 44 4f } //01 00   !.\sDO
		$a_01_2 = {61 73 64 66 34 35 36 35 36 35 36 33 34 36 34 35 } //01 00  asdf456565634645
		$a_01_3 = {2e 6d 69 78 63 72 74 } //01 00  .mixcrt
		$a_01_4 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 41 56 50 36 } //01 00  SOFTWARE\KasperskyLab\AVP6
		$a_01_5 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 41 56 50 37 } //01 00  SOFTWARE\KasperskyLab\AVP7
		$a_01_6 = {64 79 71 6d 6e 73 64 73 2f 64 79 64 } //01 00  dyqmnsds/dyd
		$a_01_7 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 67 6d 72 65 61 64 6d 65 2e 74 78 74 } //01 00  \system32\drivers\gmreadme.txt
		$a_01_8 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 38 } //01 00  SOFTWARE\KasperskyLab\protected\AVP8
		$a_00_9 = {5c 00 52 00 65 00 67 00 69 00 73 00 74 00 72 00 79 00 5c 00 4d 00 61 00 63 00 68 00 69 00 6e 00 65 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 53 00 65 00 74 00 5c 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 5c 00 73 00 64 00 74 00 72 00 } //01 00  \Registry\Machine\System\CurrentControlSet\Services\sdtr
		$a_01_10 = {60 2e 75 73 64 66 64 66 35 } //01 00  `.usdfdf5
		$a_01_11 = {5c 73 79 73 74 65 6d 33 32 5c 64 72 69 76 65 72 73 5c 73 64 74 72 2e 73 79 73 } //01 00  \system32\drivers\sdtr.sys
		$a_01_12 = {53 4f 46 54 57 41 52 45 5c 4b 61 73 70 65 72 73 6b 79 4c 61 62 5c 70 72 6f 74 65 63 74 65 64 5c 41 56 50 37 } //00 00  SOFTWARE\KasperskyLab\protected\AVP7
	condition:
		any of ($a_*)
 
}