
rule HackTool_Linux_Enum4Linux_A{
	meta:
		description = "HackTool:Linux/Enum4Linux.A,SIGNATURE_TYPE_CMDHSTR_EXT,1f 00 1f 00 0f 00 00 0a 00 "
		
	strings :
		$a_00_0 = {70 00 65 00 72 00 6c 00 } //14 00  perl
		$a_00_1 = {65 00 6e 00 75 00 6d 00 34 00 6c 00 69 00 6e 00 75 00 78 00 } //01 00  enum4linux
		$a_00_2 = {2d 00 75 00 } //01 00  -u
		$a_00_3 = {2d 00 6d 00 } //01 00  -m
		$a_00_4 = {2d 00 73 00 } //01 00  -s
		$a_00_5 = {2d 00 70 00 } //01 00  -p
		$a_00_6 = {2d 00 67 00 } //01 00  -g
		$a_00_7 = {2d 00 64 00 } //01 00  -d
		$a_00_8 = {2d 00 61 00 } //01 00  -a
		$a_00_9 = {2d 00 72 00 } //01 00  -r
		$a_00_10 = {2d 00 6c 00 } //01 00  -l
		$a_00_11 = {2d 00 6b 00 } //01 00  -k
		$a_00_12 = {2d 00 6f 00 } //01 00  -o
		$a_00_13 = {2d 00 6e 00 } //01 00  -n
		$a_00_14 = {2d 00 69 00 } //00 00  -i
	condition:
		any of ($a_*)
 
}