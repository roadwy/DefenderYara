
rule Trojan_BAT_LummaStealer_NK_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.NK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 69 8d 25 00 00 01 25 17 73 ?? 00 00 0a 13 04 06 6f ?? 00 00 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 6f 16 00 00 06 } //3
		$a_01_1 = {4a 53 79 6c 43 41 67 49 75 66 50 79 72 45 } //1 JSylCAgIufPyrE
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}