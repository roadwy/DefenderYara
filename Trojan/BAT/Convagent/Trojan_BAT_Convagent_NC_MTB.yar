
rule Trojan_BAT_Convagent_NC_MTB{
	meta:
		description = "Trojan:BAT/Convagent.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {8d 86 00 00 01 25 16 17 9c 25 17 17 9c 25 13 07 17 28 ?? 00 00 0a 26 11 07 16 91 2d 02 2b 20 11 0f 11 06 16 9a 28 ?? 00 00 0a d0 ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 74 ?? 00 00 01 51 } //5
		$a_01_1 = {46 69 72 6d 61 45 6c 65 74 74 72 6f 6e 69 63 61 44 44 54 2e 66 72 6d 46 49 52 4d 41 2e 72 65 73 6f 75 72 63 65 73 } //1 FirmaElettronicaDDT.frmFIRMA.resources
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}