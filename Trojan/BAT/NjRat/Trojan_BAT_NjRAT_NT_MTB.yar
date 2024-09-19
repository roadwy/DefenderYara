
rule Trojan_BAT_NjRAT_NT_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.NT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 09 11 06 16 11 06 8e b7 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c de 10 } //5
		$a_01_1 = {6c 48 5a 4f 65 71 48 6b 71 49 50 70 50 63 6d 6c 77 4b 70 73 44 48 48 } //1 lHZOeqHkqIPpPcmlwKpsDHH
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}