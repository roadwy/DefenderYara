
rule Trojan_BAT_FileCoder_NK_MTB{
	meta:
		description = "Trojan:BAT/FileCoder.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 08 09 11 08 16 03 6f ?? 00 00 0a 26 07 08 11 08 28 ?? 00 00 06 13 09 09 } //4
		$a_01_1 = {77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 6f 00 6c 00 64 00 2e 00 6f 00 6c 00 64 00 } //1 windows.old.old
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}