
rule Trojan_BAT_Tenga_PKZM_MTB{
	meta:
		description = "Trojan:BAT/Tenga.PKZM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 0b 01 00 70 20 2e 04 00 00 73 1d 00 00 06 73 4a 00 00 0a 0a 25 06 6f ?? 00 00 0a 6f ?? 00 00 06 0b 06 6f ?? 00 00 0a 6f ?? 00 00 06 0c 18 8d 34 00 00 01 25 16 07 a2 25 17 08 a2 28 ?? 00 00 0a 6f ?? 00 00 0a de 03 } //3
		$a_00_1 = {53 00 76 00 63 00 68 00 6f 00 73 00 74 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 SvchostController.exe
	condition:
		((#a_03_0  & 1)*3+(#a_00_1  & 1)*1) >=4
 
}