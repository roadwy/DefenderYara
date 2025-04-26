
rule Trojan_Win32_MustangPanda_RPX_MTB{
	meta:
		description = "Trojan:Win32/MustangPanda.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f 43 85 70 ff ff ff 51 50 ff d6 83 7d bc 08 8d 4d a8 6a 00 0f 43 4d a8 8d 45 8c 83 7d a0 08 51 0f 43 45 8c 50 ff d6 } //1
		$a_01_1 = {73 00 74 00 61 00 72 00 6d 00 79 00 67 00 61 00 6d 00 65 00 } //1 starmygame
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}