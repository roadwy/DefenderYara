
rule Trojan_Win32_TrickBot_GC_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 4c 24 ?? 32 54 0c ?? 88 10 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24 } //1
		$a_81_1 = {48 61 35 58 54 6b 46 57 63 72 71 4f 67 54 4b 35 65 44 30 75 77 48 4a 67 49 34 32 4e 72 70 55 6e 44 6d 39 4c 4e 58 66 38 33 6f 54 68 4d 4c 45 78 31 6b 32 6c 38 } //1 Ha5XTkFWcrqOgTK5eD0uwHJgI42NrpUnDm9LNXf83oThMLEx1k2l8
	condition:
		((#a_02_0  & 1)*1+(#a_81_1  & 1)*1) >=1
 
}