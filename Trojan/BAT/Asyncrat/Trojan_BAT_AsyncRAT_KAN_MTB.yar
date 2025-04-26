
rule Trojan_BAT_AsyncRAT_KAN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.KAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d e1 } //1
		$a_01_1 = {65 6e 63 72 79 70 74 65 64 53 68 65 6c 6c 63 6f 64 65 } //1 encryptedShellcode
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}