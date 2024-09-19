
rule Trojan_BAT_Jalapeno_NJ_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.NJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 fb 03 00 0a 6f fc 03 00 0a 28 fd 03 00 0a 28 fe 03 00 0a 28 07 00 00 2b 17 fe 02 0a 06 } //3
		$a_01_1 = {53 75 44 75 6e 67 53 6f 4c 75 6f 6e 67 } //1 SuDungSoLuong
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}