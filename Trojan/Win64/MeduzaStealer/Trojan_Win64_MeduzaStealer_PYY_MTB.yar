
rule Trojan_Win64_MeduzaStealer_PYY_MTB{
	meta:
		description = "Trojan:Win64/MeduzaStealer.PYY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c3 02 c0 8d 0c 18 41 02 c9 0f be f9 41 23 f8 8b c3 99 41 f7 fa 48 63 ca 42 0f b6 04 21 40 32 c7 42 88 04 21 ff c3 3b de 7c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}