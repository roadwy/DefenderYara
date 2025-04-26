
rule Trojan_AndroidOS_Yaats_A{
	meta:
		description = "Trojan:AndroidOS/Yaats.A,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {54 69 63 6b 54 69 63 6b 20 52 65 63 65 69 76 65 64 } //2 TickTick Received
		$a_01_1 = {73 65 72 76 69 63 65 73 2f 43 6c 69 65 6e 74 53 69 67 6e 61 6c 52 53 65 72 76 69 63 65 } //2 services/ClientSignalRService
		$a_01_2 = {75 69 2f 4e 75 46 36 } //2 ui/NuF6
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}