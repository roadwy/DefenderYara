
rule Trojan_Win32_Makoob_SLOU_MTB{
	meta:
		description = "Trojan:Win32/Makoob.SLOU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 00 6f 00 72 00 74 00 74 00 6e 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 20 00 74 00 72 00 61 00 70 00 70 00 79 00 } //2 forttningernes trappy
		$a_01_1 = {73 00 63 00 72 00 65 00 65 00 6e 00 69 00 6e 00 67 00 65 00 72 00 6e 00 65 00 73 00 20 00 72 00 65 00 76 00 65 00 72 00 73 00 69 00 62 00 69 00 6c 00 69 00 74 00 65 00 74 00 20 00 65 00 6b 00 76 00 69 00 70 00 65 00 72 00 69 00 6e 00 67 00 73 00 68 00 61 00 6e 00 64 00 6c 00 65 00 72 00 } //2 screeningernes reversibilitet ekviperingshandler
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}