
rule Trojan_Win32_Qakbot_W_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.W!MTB,SIGNATURE_TYPE_PEHSTR_EXT,18 00 18 00 08 00 00 03 00 "
		
	strings :
		$a_80_0 = {42 75 72 6e 73 74 61 72 } //Burnstar  03 00 
		$a_80_1 = {50 65 72 73 6f 6e 66 69 6e 64 } //Personfind  03 00 
		$a_80_2 = {50 6c 61 6e 74 63 6f 76 65 72 } //Plantcover  03 00 
		$a_80_3 = {6f 69 6c 5c 70 61 74 74 65 72 5c 74 68 6f 73 65 2e 70 64 62 } //oil\patter\those.pdb  03 00 
		$a_80_4 = {49 73 44 65 62 75 67 67 65 72 50 72 65 73 65 6e 74 } //IsDebuggerPresent  03 00 
		$a_80_5 = {49 6e 74 65 72 6c 6f 63 6b 65 64 50 75 73 68 45 6e 74 72 79 53 4c 69 73 74 } //InterlockedPushEntrySList  03 00 
		$a_80_6 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 41 } //OutputDebugStringA  03 00 
		$a_80_7 = {49 73 50 72 6f 63 65 73 73 6f 72 46 65 61 74 75 72 65 50 72 65 73 65 6e 74 } //IsProcessorFeaturePresent  00 00 
	condition:
		any of ($a_*)
 
}