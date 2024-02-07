
rule HackTool_Win32_PsAttack_A{
	meta:
		description = "HackTool:Win32/PsAttack.A,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 00 6d 00 73 00 69 00 55 00 74 00 69 00 6c 00 73 00 27 00 29 00 2e 00 47 00 65 00 74 00 46 00 69 00 65 00 6c 00 64 00 28 00 27 00 61 00 6d 00 73 00 69 00 49 00 6e 00 69 00 74 00 46 00 61 00 69 00 6c 00 65 00 64 00 27 00 2c 00 27 00 4e 00 6f 00 6e 00 50 00 75 00 62 00 6c 00 69 00 63 00 2c 00 53 00 74 00 61 00 74 00 69 00 63 00 27 00 29 00 2e 00 53 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00 28 00 24 00 6e 00 75 00 6c 00 6c 00 2c 00 24 00 74 00 72 00 75 00 65 00 29 00 } //00 00  AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
	condition:
		any of ($a_*)
 
}