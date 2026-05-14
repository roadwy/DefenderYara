
rule Trojan_BAT_Darktortilla_MCQ_MTB{
	meta:
		description = "Trojan:BAT/Darktortilla.MCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 00 61 00 6d 00 61 00 74 00 00 03 2f 00 00 13 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 0d 39 00 34 00 32 00 33 00 36 00 31 00 00 0f 4c 00 20 00 6f 00 20 00 61 00 20 00 64 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}