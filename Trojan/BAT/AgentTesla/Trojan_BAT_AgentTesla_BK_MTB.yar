
rule Trojan_BAT_AgentTesla_BK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_02_0 = {0a 0b 1e 8d ?? ?? ?? ?? 0c 07 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 6f ?? ?? ?? ?? 16 08 16 1e 28 ?? ?? ?? ?? 06 08 6f ?? ?? ?? ?? 06 18 6f ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 03 16 03 8e 69 6f } //10
		$a_81_1 = {46 69 6c 6c 52 65 63 74 61 } //1 FillRecta
	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1) >=11
 
}
rule Trojan_BAT_AgentTesla_BK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 38 00 2e 00 33 00 34 00 2e 00 31 00 38 00 37 00 2e 00 31 00 37 00 30 00 2f 00 70 00 72 00 69 00 76 00 2e 00 64 00 6c 00 6c 00 } //2 http://188.34.187.170/priv.dll
		$a_01_1 = {73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 6d 00 6f 00 63 00 2e 00 70 00 70 00 61 00 64 00 72 00 6f 00 63 00 73 00 69 00 64 00 2e 00 6e 00 64 00 63 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00 } //2 stnemhcatta/moc.ppadrocsid.ndc//:sptth
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 69 00 63 00 61 00 6e 00 68 00 61 00 7a 00 69 00 70 00 2e 00 63 00 6f 00 6d 00 } //2 http://icanhazip.com
		$a_01_3 = {43 3a 5c 55 73 65 72 73 5c 78 78 78 5c 44 65 73 6b 74 6f 70 5c 49 50 46 41 4a 4e 59 50 52 4f 47 52 41 4d 5c 43 6c 69 65 6e 74 5c 43 6c 69 65 6e 74 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c 43 6c 69 65 6e 74 2e 70 64 62 } //2 C:\Users\xxx\Desktop\IPFAJNYPROGRAM\Client\Client\obj\x86\Release\Client.pdb
		$a_01_4 = {44 65 62 75 67 67 61 62 6c 65 41 74 74 72 69 62 75 74 65 } //1 DebuggableAttribute
		$a_01_5 = {46 6f 72 6d 31 5f 4c 6f 61 64 } //1 Form1_Load
		$a_01_6 = {44 69 73 70 6f 73 65 } //1 Dispose
		$a_01_7 = {43 6f 6e 63 61 74 } //1 Concat
		$a_01_8 = {44 65 62 75 67 67 65 72 4e 6f 6e 55 73 65 72 43 6f 64 65 41 74 74 72 69 62 75 74 65 } //1 DebuggerNonUserCodeAttribute
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}