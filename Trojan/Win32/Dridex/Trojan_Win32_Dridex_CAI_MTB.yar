
rule Trojan_Win32_Dridex_CAI_MTB{
	meta:
		description = "Trojan:Win32/Dridex.CAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 02 00 "
		
	strings :
		$a_81_0 = {63 72 65 65 70 69 6e 67 43 68 61 74 68 37 72 75 6c 65 73 61 79 69 6e 67 77 68 6f 73 65 74 72 65 65 } //02 00  creepingChath7rulesayingwhosetree
		$a_81_1 = {73 65 65 64 6d 5a 79 6f 75 44 72 65 70 6c 65 6e 69 73 68 64 61 79 6e } //02 00  seedmZyouDreplenishdayn
		$a_81_2 = {49 74 73 65 6c 66 75 6e 64 65 72 64 69 76 69 64 65 64 68 6d 6f 76 65 74 68 6c 69 6b 65 6e 65 73 73 66 72 75 69 74 66 75 6c 61 } //02 00  Itselfunderdividedhmovethlikenessfruitfula
		$a_81_3 = {47 73 65 61 73 6f 6e 73 77 68 69 63 68 74 68 65 69 72 61 67 72 61 73 73 6f 55 6f 6e 65 66 6c 79 } //02 00  GseasonswhichtheiragrassoUonefly
		$a_81_4 = {43 72 65 61 74 65 54 69 6d 65 72 51 75 65 75 65 } //00 00  CreateTimerQueue
	condition:
		any of ($a_*)
 
}