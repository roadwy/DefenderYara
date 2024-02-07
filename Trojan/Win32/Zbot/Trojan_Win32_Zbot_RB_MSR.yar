
rule Trojan_Win32_Zbot_RB_MSR{
	meta:
		description = "Trojan:Win32/Zbot.RB!MSR,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 6e 74 69 72 65 70 75 62 6c 69 63 61 6e 69 73 6d } //01 00  Antirepublicanism
		$a_01_1 = {44 69 73 65 73 74 61 62 6c 69 73 6d 65 6e 74 61 72 69 61 6e 69 73 6d } //01 00  Disestablismentarianism
		$a_01_2 = {42 72 6f 6e 63 68 6f 73 20 73 70 69 73 65 } //01 00  Bronchos spise
		$a_01_3 = {69 6e 73 65 63 75 72 61 74 69 6f 6e } //01 00  insecuration
		$a_01_4 = {47 75 6e 73 69 67 68 74 37 } //01 00  Gunsight7
		$a_01_5 = {69 64 6f 6e 65 6f 75 73 6e 65 73 73 } //01 00  idoneousness
		$a_01_6 = {66 72 6f 6c 69 63 6b 6c 79 } //00 00  frolickly
	condition:
		any of ($a_*)
 
}