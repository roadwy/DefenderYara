
rule Trojan_BAT_Rhadamanthys_ARM_MTB{
	meta:
		description = "Trojan:BAT/Rhadamanthys.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {6c 03 6c 5b 28 ?? 00 00 06 69 0a 06 8d ?? 00 00 01 0b 16 0c 2b 2b 00 08 03 5a 0d 7e ?? 00 00 04 03 02 6f ?? 00 00 0a 09 59 28 ?? 00 00 06 13 04 07 08 02 09 11 04 6f ?? 00 00 0a a2 00 08 17 58 0c 08 06 fe 04 13 06 11 06 } //2
		$a_01_1 = {6e 00 65 00 77 00 63 00 72 00 79 00 70 00 74 00 65 00 72 00 6e 00 6f 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 2e 00 65 00 78 00 65 00 } //1 newcrypternoprocess.exe
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}