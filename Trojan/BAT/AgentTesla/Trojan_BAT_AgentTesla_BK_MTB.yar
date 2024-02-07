
rule Trojan_BAT_AgentTesla_BK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 0a 00 "
		
	strings :
		$a_02_0 = {0a 0b 1e 8d 90 01 04 0c 07 28 90 01 04 72 90 01 04 6f 90 01 04 6f 90 01 04 16 08 16 1e 28 90 01 04 06 08 6f 90 01 04 06 18 6f 90 01 04 06 6f 90 01 04 03 16 03 8e 69 6f 90 00 } //01 00 
		$a_81_1 = {46 69 6c 6c 52 65 63 74 61 } //00 00  FillRecta
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_BK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 02 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 38 00 2e 00 33 00 34 00 2e 00 31 00 38 00 37 00 2e 00 31 00 37 00 30 00 2f 00 70 00 72 00 69 00 76 00 2e 00 64 00 6c 00 6c 00 } //02 00  http://188.34.187.170/priv.dll
		$a_01_1 = {73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 6d 00 6f 00 63 00 2e 00 70 00 70 00 61 00 64 00 72 00 6f 00 63 00 73 00 69 00 64 00 2e 00 6e 00 64 00 63 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00 } //02 00  stnemhcatta/moc.ppadrocsid.ndc//:sptth
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 63 00 61 00 6e 00 68 00 61 00 7a 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 } //02 00  http://icanhazip.com
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 78 78 78 5c 44 65 73 6b 74 6f 70 5c 49 50 46 41 4a 4e 59 50 52 4f 47 52 41 4d 5c 43 6c 69 65 6e 74 5c 43 6c 69 65 6e 74 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 43 6c 69 65 6e 74 2e 70 64 62 } //01 00  C:\Users\xxx\Desktop\IPFAJNYPROGRAM\Client\Client\obj\x86\Release\Client.pdb
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //01 00  DebuggableAttribute
		$a_01_5 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //01 00  Form1_Load
		$a_01_6 = {44 69 73 70 6f 73 65 } //01 00  Dispose
		$a_01_7 = {43 6f 6e 63 61 74 } //01 00  Concat
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //00 00  DebuggerNonUserCodeAttribute
	condition:
		any of ($a_*)
 
}