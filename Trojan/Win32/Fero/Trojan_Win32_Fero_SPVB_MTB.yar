
rule Trojan_Win32_Fero_SPVB_MTB{
	meta:
		description = "Trojan:Win32/Fero.SPVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_81_0 = {4f 73 54 6c 68 74 6c 6f 68 65 } //2 OsTlhtlohe
		$a_01_1 = {68 72 74 62 64 64 64 36 39 2e 64 6c 6c } //1 hrtbddd69.dll
		$a_01_2 = {4f 73 54 6c 68 74 6c 6f 68 65 } //1 OsTlhtlohe
	condition:
		((#a_81_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}