
rule Backdoor_BAT_XWormRAT_D_MTB{
	meta:
		description = "Backdoor:BAT/XWormRAT.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 00 04 20 e8 03 00 00 d8 7e } //01 00 
		$a_01_1 = {43 68 65 63 6b 52 65 6d 6f 74 65 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //00 00  CheckRemoteDebuggerPresent
	condition:
		any of ($a_*)
 
}