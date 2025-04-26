
rule TrojanSpy_BAT_ZeroLogger_A{
	meta:
		description = "TrojanSpy:BAT/ZeroLogger.A,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 2f 20 5a 65 72 6f 4c 6f 67 67 65 72 20 7c 20 4d 6f 6e 69 74 6f 72 20 7c 20 4c 6f 67 73 20 5c } //1 // ZeroLogger | Monitor | Logs \
		$a_01_1 = {5a 65 72 6f 20 4c 6f 67 67 65 72 20 2d 20 59 6f 75 20 47 6f 74 20 4c 6f 67 73 21 } //1 Zero Logger - You Got Logs!
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}