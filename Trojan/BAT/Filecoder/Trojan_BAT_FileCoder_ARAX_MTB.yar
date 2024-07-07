
rule Trojan_BAT_FileCoder_ARAX_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {63 6c 69 70 70 79 5f 72 61 6e 73 6f 6d 77 61 72 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //clippy_ransomware.Properties.Resources  2
		$a_80_1 = {65 6e 63 72 79 70 74 65 64 20 66 69 6c 65 73 } //encrypted files  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}