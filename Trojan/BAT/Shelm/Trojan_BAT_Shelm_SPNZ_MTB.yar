
rule Trojan_BAT_Shelm_SPNZ_MTB{
	meta:
		description = "Trojan:BAT/Shelm.SPNZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 0c 7e 90 01 03 0a 20 90 01 03 00 20 90 01 03 00 1f 40 28 90 01 03 06 0d 07 16 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}