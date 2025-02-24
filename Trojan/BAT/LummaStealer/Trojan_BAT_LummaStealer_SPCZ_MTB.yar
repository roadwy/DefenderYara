
rule Trojan_BAT_LummaStealer_SPCZ_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.SPCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 07 06 09 06 08 91 9c 06 08 11 07 9c dd } //4
		$a_01_1 = {5d 13 06 02 11 05 8f 1d 00 00 01 25 47 06 11 06 91 61 d2 52 11 05 17 58 13 05 } //1
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}