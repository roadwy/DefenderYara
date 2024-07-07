
rule Trojan_Win32_Qukart_ASCB_MTB{
	meta:
		description = "Trojan:Win32/Qukart.ASCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {55 89 e5 83 ec 0c 56 57 bf af 19 aa 46 89 f8 01 f8 89 c7 8d 45 f8 50 8d 45 fc 50 6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 ff 75 0c ff 75 08 e8 } //2
		$a_01_1 = {55 89 e5 51 56 57 bf 48 3b a2 7f 81 ef dc 4b 00 00 8d 45 fc 50 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}