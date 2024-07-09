
rule Trojan_BAT_Barys_AMAD_MTB{
	meta:
		description = "Trojan:BAT/Barys.AMAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 07 11 04 17 73 ?? 00 00 0a 0c 28 ?? ?? 00 06 16 9a 75 ?? 00 00 1b 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 05 de 18 } //1
		$a_81_1 = {39 62 7a 38 67 72 33 70 36 79 66 74 74 62 6c 73 38 37 6b 78 36 75 70 38 64 66 66 37 6a 6d 71 37 } //1 9bz8gr3p6yfttbls87kx6up8dff7jmq7
		$a_81_2 = {4d 70 33 4c 61 6d 65 41 75 64 69 6f 45 6e 63 6f 64 65 72 } //1 Mp3LameAudioEncoder
		$a_81_3 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}