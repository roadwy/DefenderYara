
rule Trojan_Win32_Agent_QQ{
	meta:
		description = "Trojan:Win32/Agent.QQ,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_03_0 = {8a 14 30 80 c2 7a 88 14 30 8b 45 ?? 80 34 30 19 } //1
		$a_00_1 = {48 41 43 4b 35 39 30 4e 45 54 53 56 43 53 5f 30 78 25 78 } //1 HACK590NETSVCS_0x%x
		$a_00_2 = {25 73 59 53 54 45 4d 72 4f 4f 54 25 5c 73 59 53 54 45 4d 33 32 5c 53 56 43 48 4f 53 54 2e 45 58 45 20 2d 4b 20 4e 45 54 53 56 43 53 } //1 %sYSTEMrOOT%\sYSTEM32\SVCHOST.EXE -K NETSVCS
		$a_00_3 = {25 73 5c 70 63 67 61 6d 65 2e 64 6c 6c } //1 %s\pcgame.dll
		$a_00_4 = {57 48 4d 5f 53 65 72 76 65 72 5f 55 70 64 61 74 65 } //1 WHM_Server_Update
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}