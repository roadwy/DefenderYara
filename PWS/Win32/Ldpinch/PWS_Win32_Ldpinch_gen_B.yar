
rule PWS_Win32_Ldpinch_gen_B{
	meta:
		description = "PWS:Win32/Ldpinch.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 0d 00 00 03 00 "
		
	strings :
		$a_01_0 = {68 6f 74 6d 61 69 6c 2e 63 6f 6d 00 73 65 6e 64 6d 61 69 6c 00 } //01 00 
		$a_01_1 = {61 63 63 6f 75 6e 74 73 3d 25 } //01 00  accounts=%
		$a_01_2 = {3c 2f 6d 62 6f 64 79 3e } //01 00  </mbody>
		$a_01_3 = {3c 2f 61 64 64 72 73 3e } //01 00  </addrs>
		$a_01_4 = {3c 2f 74 61 73 6b 73 3e } //01 00  </tasks>
		$a_01_5 = {25 25 66 72 6f 6d 6f 75 74 6c 6b } //01 00  %%fromoutlk
		$a_01_6 = {25 25 73 6e 64 72 64 6f 6d 61 69 6e } //01 00  %%sndrdomain
		$a_01_7 = {25 25 73 65 6c 66 64 6f 6d 61 69 6e } //01 00  %%selfdomain
		$a_01_8 = {25 25 72 6e 64 6e 61 6d 65 } //01 00  %%rndname
		$a_01_9 = {25 25 72 6e 64 77 6f 72 64 } //01 00  %%rndword
		$a_01_10 = {25 25 72 6e 64 6d 69 78 } //01 00  %%rndmix
		$a_01_11 = {25 64 2e 25 64 2e 25 64 2e 25 64 2e 69 6e 2d 61 64 64 72 2e } //01 00  %d.%d.%d.%d.in-addr.
		$a_01_12 = {77 61 62 69 6d 70 6f 72 74 65 72 } //00 00  wabimporter
	condition:
		any of ($a_*)
 
}