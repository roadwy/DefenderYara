
rule Trojan_BAT_AgentTesla_JMD_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_81_0 = {24 31 33 34 31 39 63 31 37 2d 61 37 62 62 2d 34 63 31 30 2d 38 37 66 37 2d 38 35 66 65 66 38 30 63 64 62 66 31 } //01 00  $13419c17-a7bb-4c10-87f7-85fef80cdbf1
		$a_81_1 = {30 2e 33 30 33 31 39 5c 52 65 67 41 73 6d 2e 65 78 65 } //01 00  0.30319\RegAsm.exe
		$a_81_2 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //01 00  InvokeMember
		$a_81_3 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //01 00  DownloadData
		$a_81_4 = {38 37 37 36 38 39 35 38 32 33 39 35 37 31 39 37 32 34 2f 38 37 37 36 39 30 30 } //01 00  877689582395719724/8776900
		$a_81_5 = {77 69 6e 6f 6d 6f 65 72 61 2e 6f 70 65 72 61 76 6e 62 } //01 00  winomoera.operavnb
		$a_81_6 = {4b 61 66 65 4f 74 6f 6d 61 73 79 6f 6e 2e 63 73 } //01 00  KafeOtomasyon.cs
		$a_81_7 = {44 65 62 75 67 5c 4b 61 66 65 4f 74 6f 6d 61 73 79 6f 6e } //01 00  Debug\KafeOtomasyon
		$a_81_8 = {44 65 62 75 67 67 65 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 } //01 00  DebuggerBrowsableState
		$a_81_9 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}