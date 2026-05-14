
rule Trojan_BAT_Heracles_GPSH_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {57 00 61 00 6e 00 6e 00 61 00 43 00 72 00 79 00 2f 00 72 00 65 00 6c 00 65 00 61 00 73 00 65 00 73 00 2f 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 2f 00 41 00 6e 00 74 00 69 00 5f 00 57 00 61 00 6e 00 6e 00 61 00 43 00 72 00 79 00 2f 00 57 00 61 00 6e 00 6e 00 61 00 43 00 72 00 79 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}