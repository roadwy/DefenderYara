
rule Trojan_BAT_MeduzaStealer_AMZ_MTB{
	meta:
		description = "Trojan:BAT/MeduzaStealer.AMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 72 2e 01 00 70 a2 25 17 72 01 00 00 70 28 ?? 00 00 06 a2 25 18 72 5a 01 00 70 a2 25 19 06 a2 25 1a 72 12 01 00 70 a2 28 } //3
		$a_01_1 = {31 00 34 00 37 00 2e 00 34 00 35 00 2e 00 34 00 37 00 2e 00 31 00 35 00 2f 00 64 00 75 00 73 00 63 00 68 00 6e 00 6f 00 2e 00 65 00 78 00 65 00 } //2 147.45.47.15/duschno.exe
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}