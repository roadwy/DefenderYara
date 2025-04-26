
rule Trojan_BAT_FormBook_MBWB_MTB{
	meta:
		description = "Trojan:BAT/FormBook.MBWB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 4b 55 68 4a 53 57 63 57 50 51 64 50 53 61 62 53 00 4c 4c 4d 67 67 59 4b 64 64 4a 4e 4c 4c 62 4b 56 4d 00 66 65 4e 52 64 4e 58 59 61 65 61 56 61 } //2
		$a_01_1 = {4e 52 65 4e 4c 58 65 61 67 56 51 64 54 4e 61 65 58 } //1 NReNLXeagVQdTNaeX
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}