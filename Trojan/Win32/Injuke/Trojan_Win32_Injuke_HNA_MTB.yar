
rule Trojan_Win32_Injuke_HNA_MTB{
	meta:
		description = "Trojan:Win32/Injuke.HNA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 68 74 74 fb df b6 ff 70 3a 2f 2f 38 39 2e 31 31 06 36 37 0c 35 34 2f 74 65 73 74 6f 35 2f 39 bf bd dd 0e 6b 75 02 74 72 75 26 6e 65 74 37 00 2e 69 6e 66 6f 2f 4a 1e 60 ff 68 6f 6d 65 2e 67 69 66 49 38 38 38 8b 6a a1 9d 39 38 93 01 ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}