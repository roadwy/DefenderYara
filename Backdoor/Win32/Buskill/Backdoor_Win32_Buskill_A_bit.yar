
rule Backdoor_Win32_Buskill_A_bit{
	meta:
		description = "Backdoor:Win32/Buskill.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {4f 75 72 20 64 65 73 74 69 6e 79 20 64 65 70 65 6e 64 73 20 6f 6e 6c 79 20 6f 6e 20 75 73 } //01 00  Our destiny depends only on us
		$a_01_1 = {69 66 20 6e 6f 74 20 68 61 70 70 65 6e 20 73 6f } //01 00  if not happen so
		$a_01_2 = {64 6f 20 79 6f 75 20 6b 6e 6f 77 20 4a 6f 68 6e 20 52 65 6d 62 6f } //01 00  do you know John Rembo
		$a_01_3 = {69 74 20 69 73 20 72 65 70 75 74 61 74 69 6f 6e } //01 00  it is reputation
		$a_01_4 = {4e 65 76 65 72 20 66 6f 72 67 65 74 20 79 6f 75 72 20 66 72 69 65 6e 64 73 } //01 00  Never forget your friends
		$a_01_5 = {69 74 20 63 68 61 6e 67 65 73 20 65 76 65 72 79 20 64 61 79 } //00 00  it changes every day
	condition:
		any of ($a_*)
 
}