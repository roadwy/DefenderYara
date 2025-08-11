
rule Trojan_Win32_Blackmoon_GAS_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.GAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 5d bc 8b 5d bc 8a 03 25 ff 00 00 00 89 45 b4 db 45 b4 dd 5d b4 dd 45 b4 db 45 f4 dd 5d ac dc 65 ac db 45 f8 dd 5d a4 dc 65 a4 dd 5d 9c dd 45 9c e8 97 fd ff ff 68 01 01 00 80 6a 00 50 68 01 00 00 00 bb 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}