
rule Trojan_BAT_Jalapeno_SP_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.SP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 09 06 09 91 07 09 07 8e 69 5d 91 61 d2 9c 09 17 58 0d 09 06 8e 69 } //2
		$a_81_1 = {53 68 61 72 70 45 66 73 50 6f 74 61 74 6f 2e 65 78 65 } //1 SharpEfsPotato.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*1) >=3
 
}