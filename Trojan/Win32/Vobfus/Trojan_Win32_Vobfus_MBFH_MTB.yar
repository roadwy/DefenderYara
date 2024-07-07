
rule Trojan_Win32_Vobfus_MBFH_MTB{
	meta:
		description = "Trojan:Win32/Vobfus.MBFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 00 28 30 41 00 1c 81 40 00 dc 8e 40 00 20 6f 40 00 44 6f 40 } //1
		$a_01_1 = {71 40 00 00 f8 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 3c 6a 40 00 3c 6a 40 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}