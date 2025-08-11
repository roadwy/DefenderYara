
rule Trojan_Win32_PonyStealer_DAE_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.DAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {c7 85 f0 fd ff ff 8c 23 00 00 c7 85 f4 fd ff ff 05 00 00 00 83 a5 30 ff ff ff 00 eb } //2
		$a_01_1 = {58 31 30 89 8d 80 00 00 00 b9 c3 13 9f 76 } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}