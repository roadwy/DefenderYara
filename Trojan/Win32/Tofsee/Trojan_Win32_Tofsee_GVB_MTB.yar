
rule Trojan_Win32_Tofsee_GVB_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.GVB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 db 15 98 ba 31 05 1c 94 41 00 68 } //3
		$a_01_1 = {0b 02 83 c2 04 f7 d8 83 c0 da 83 e8 02 83 e8 ff 29 f0 8d 30 6a 00 8f 01 01 01 83 e9 fc 83 c3 fc 85 db 75 da } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}