
rule Trojan_BAT_Heracles_GPAL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GPAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_81_0 = {61 70 73 74 6f 72 69 2e 72 75 2f 70 61 6e 65 6c 2f 75 70 6c 6f 61 64 73 2f } //4 apstori.ru/panel/uploads/
		$a_81_1 = {43 6f 6d 70 72 65 73 73 65 64 42 79 74 65 73 } //1 CompressedBytes
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}