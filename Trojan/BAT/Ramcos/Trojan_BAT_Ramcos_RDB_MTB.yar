
rule Trojan_BAT_Ramcos_RDB_MTB{
	meta:
		description = "Trojan:BAT/Ramcos.RDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {11 10 11 2f 11 1f 59 61 13 10 11 1f 19 11 10 58 1e 63 59 13 } //01 00  ထ⼑ἑ慙ဓἑᄙ堐挞ፙ
		$a_01_1 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 4d 00 65 00 6d 00 53 00 69 00 6d 00 } //00 00  VirtualMemSim
	condition:
		any of ($a_*)
 
}