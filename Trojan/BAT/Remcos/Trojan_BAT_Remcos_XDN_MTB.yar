
rule Trojan_BAT_Remcos_XDN_MTB{
	meta:
		description = "Trojan:BAT/Remcos.XDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 20 80 00 00 00 2b 49 28 90 01 03 0a 72 90 01 03 70 6f 90 01 03 0a 7e 02 00 00 04 20 e8 03 00 00 73 18 00 00 0a 0c 07 08 07 6f 90 01 03 0a 90 00 } //2
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}