
rule Trojan_BAT_DllInject_RRI_MTB{
	meta:
		description = "Trojan:BAT/DllInject.RRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {09 12 04 28 [0-04] 0a 7e 39 00 00 04 06 6f [0-04] 0a 2c 05 14 13 05 de 71 de 0b } //1
		$a_03_1 = {73 dd 00 00 0a 0d 08 09 28 [0-04] 06 09 16 6a 6f [0-04] 0a 09 13 04 de 1c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}