
rule Trojan_Win32_Nymeria_RPO_MTB{
	meta:
		description = "Trojan:Win32/Nymeria.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {43 4f 4e 53 4f 4c 45 53 54 41 54 45 20 2f 48 69 64 65 } //01 00  CONSOLESTATE /Hide
		$a_01_1 = {65 63 68 6f 20 47 45 54 20 46 55 43 4b 45 44 20 4e 49 47 47 45 } //01 00  echo GET FUCKED NIGGE
		$a_01_2 = {73 74 61 72 74 20 70 69 6e 67 20 32 30 38 2e 36 37 2e 32 32 32 2e 32 32 32 20 2d 74 20 2d 6c 20 36 35 35 30 30 } //01 00  start ping 208.67.222.222 -t -l 65500
		$a_01_3 = {74 61 73 6b 6b 69 6c 6c 20 2f 46 20 2f 49 4d 20 74 61 73 6b 6d 67 72 2e 65 78 65 } //01 00  taskkill /F /IM taskmgr.exe
		$a_01_4 = {67 6f 74 6f 20 64 69 65 } //00 00  goto die
	condition:
		any of ($a_*)
 
}