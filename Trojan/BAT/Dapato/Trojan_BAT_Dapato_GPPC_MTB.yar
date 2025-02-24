
rule Trojan_BAT_Dapato_GPPC_MTB{
	meta:
		description = "Trojan:BAT/Dapato.GPPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 09 07 8e b7 5d 91 61 02 50 09 17 d6 02 50 8e b7 5d 91 da } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}