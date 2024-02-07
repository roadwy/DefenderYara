
rule Trojan_Win32_Nerino_A_bit{
	meta:
		description = "Trojan:Win32/Nerino.A!bit,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 4e 65 72 69 6e 6f 20 42 4f 54 4e 45 54 } //01 00  iNerino BOTNET
		$a_01_1 = {53 61 76 65 53 63 72 65 65 6e 73 68 6f 74 54 6f 46 69 6c 65 } //01 00  SaveScreenshotToFile
		$a_01_2 = {73 63 68 74 61 73 6b 73 2e 65 78 65 20 2f 63 72 65 61 74 65 20 2f 74 6e 20 53 79 73 74 65 6d 5c 53 79 73 74 65 6d 55 70 64 61 74 65 } //00 00  schtasks.exe /create /tn System\SystemUpdate
	condition:
		any of ($a_*)
 
}