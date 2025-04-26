
rule Trojan_BAT_Meterpreter_MBM_MTB{
	meta:
		description = "Trojan:BAT/Meterpreter.MBM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 47 00 78 00 6a 00 6b 00 77 00 2f 00 47 00 44 00 41 00 35 00 6a 00 52 00 55 00 56 00 48 00 62 00 52 00 4c 00 76 00 33 00 75 00 44 00 51 00 70 00 64 00 44 00 68 00 57 00 69 00 } //1 /Gxjkw/GDA5jRUVHbRLv3uDQpdDhWi
		$a_81_1 = {63 4b 4a 6f 4b 72 7a 4f 31 69 66 6f 58 56 41 33 43 6d 52 51 57 78 79 63 51 35 6c 56 75 43 6c 6b } //1 cKJoKrzO1ifoXVA3CmRQWxycQ5lVuClk
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}