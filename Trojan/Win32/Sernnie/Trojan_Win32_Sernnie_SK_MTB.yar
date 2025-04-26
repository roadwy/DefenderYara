
rule Trojan_Win32_Sernnie_SK_MTB{
	meta:
		description = "Trojan:Win32/Sernnie.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {49 6e 66 65 63 74 44 72 69 76 65 } //1 InfectDrive
		$a_81_1 = {4e 65 74 42 6f 74 2e 76 62 70 } //1 NetBot.vbp
		$a_81_2 = {75 39 31 30 34 38 38 33 30 31 2e 6e 65 74 62 6f 78 30 30 31 } //1 u910488301.netbox001
		$a_81_3 = {5c 4f 4b 5c 42 4f 54 5c 6e 62 2e 65 78 65 20 2b 73 20 2b 68 20 2b 72 } //1 \OK\BOT\nb.exe +s +h +r
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}