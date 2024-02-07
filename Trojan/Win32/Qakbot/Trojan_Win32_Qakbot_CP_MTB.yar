
rule Trojan_Win32_Qakbot_CP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {42 3f 30 3f 24 57 65 61 6b 49 6d 70 6c 48 65 6c 70 65 72 31 40 56 58 49 6e 74 65 72 61 63 74 69 6f 6e 48 61 6e 64 6c 65 72 32 40 74 61 73 6b 40 73 74 61 72 40 73 75 6e 40 63 6f 6d 40 40 40 63 70 70 75 40 40 51 41 45 40 58 5a } //01 00  B?0?$WeakImplHelper1@VXInteractionHandler2@task@star@sun@com@@@cppu@@QAE@XZ
		$a_01_1 = {42 3f 30 58 4d 4c 4e 61 6d 65 73 70 61 63 65 73 40 66 72 61 6d 65 77 6f 72 6b 40 40 51 41 45 40 58 5a } //01 00  B?0XMLNamespaces@framework@@QAE@XZ
		$a_01_2 = {42 3f 31 41 63 74 69 6f 6e 54 72 69 67 67 65 72 50 72 6f 70 65 72 74 79 53 65 74 40 66 72 61 6d 65 77 6f 72 6b 40 40 55 41 45 40 58 5a } //01 00  B?1ActionTriggerPropertySet@framework@@UAE@XZ
		$a_01_3 = {42 3f 31 55 6e 64 6f 4d 61 6e 61 67 65 72 48 65 6c 70 65 72 40 66 72 61 6d 65 77 6f 72 6b 40 40 51 41 45 40 58 5a } //0a 00  B?1UndoManagerHelper@framework@@QAE@XZ
		$a_01_4 = {47 47 31 30 } //00 00  GG10
	condition:
		any of ($a_*)
 
}