
rule Trojan_BAT_AveMaria_AARV_MTB{
	meta:
		description = "Trojan:BAT/AveMaria.AARV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 3d 7e ?? 00 00 04 11 06 7e ?? 00 00 04 11 06 91 7e ?? 00 00 04 61 7e ?? 00 00 04 09 91 61 28 ?? 00 00 06 9c 09 7e ?? 00 00 04 8e 69 17 59 33 04 16 0d 2b 04 09 17 58 0d 11 06 17 58 13 06 11 06 7e ?? 00 00 04 8e 69 17 59 31 b6 } //4
		$a_01_1 = {43 00 53 00 68 00 61 00 72 00 70 00 47 00 6f 00 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 CSharpGoWinForm.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}