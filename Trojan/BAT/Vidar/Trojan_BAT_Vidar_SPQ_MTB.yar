
rule Trojan_BAT_Vidar_SPQ_MTB{
	meta:
		description = "Trojan:BAT/Vidar.SPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 06 1b 8d 09 00 00 01 25 16 20 5c 04 00 00 28 ?? ?? ?? 06 a2 25 17 07 a2 25 18 20 74 04 00 00 28 ?? ?? ?? 06 a2 25 19 08 a2 25 1a 20 7e 04 00 00 28 ?? ?? ?? 06 a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 38 46 00 00 00 } //3
		$a_01_1 = {52 65 63 65 69 76 65 43 61 70 74 75 72 65 52 65 71 75 65 73 74 } //1 ReceiveCaptureRequest
		$a_01_2 = {52 65 63 65 69 76 65 45 6e 63 72 79 70 74 69 6f 6e 53 74 61 74 75 73 } //1 ReceiveEncryptionStatus
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}