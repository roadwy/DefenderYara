
rule Trojan_BAT_LummaStealer_SP_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {11 05 11 07 1f 28 5a 58 13 08 28 1e 00 00 0a 07 11 08 1e 6f 1f 00 00 0a 17 8d 1f 00 00 01 6f 20 00 00 0a } //2
		$a_01_1 = {43 68 61 72 74 65 72 2e 65 78 65 } //2 Charter.exe
		$a_01_2 = {24 61 63 30 34 39 62 66 61 2d 32 64 64 38 2d 34 66 31 61 2d 39 33 31 34 2d 31 31 65 33 66 65 64 36 31 34 35 34 } //2 $ac049bfa-2dd8-4f1a-9314-11e3fed61454
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}