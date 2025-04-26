
rule Trojan_BAT_Heracles_MBXT_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MBXT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 76 6c 45 64 69 74 6f 72 2e 41 41 41 41 41 41 41 41 41 41 41 2e 72 65 73 6f 75 72 63 65 } //3 LvlEditor.AAAAAAAAAAA.resource
		$a_01_1 = {52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73 } //2 Rfc2898DeriveBytes
		$a_01_2 = {41 69 6e 74 61 63 } //1 Aintac
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=6
 
}