
rule Trojan_BAT_AsyncRAT_RDR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 70 6f 6c 6c 6f 20 4a 75 73 74 69 63 65 20 53 63 72 69 70 74 20 45 64 69 74 6f 72 } //1 Apollo Justice Script Editor
		$a_01_1 = {42 65 64 73 2d 50 72 6f 74 65 63 74 6f 72 } //1 Beds-Protector
		$a_01_2 = {53 74 6f 70 20 54 72 79 69 6e 67 20 54 6f 20 55 6e 70 61 63 6b 20 74 68 65 20 74 6f 6f 6c 21 } //1 Stop Trying To Unpack the tool!
		$a_01_3 = {42 61 62 65 6c 4f 62 66 75 73 63 61 74 6f 72 } //1 BabelObfuscator
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}