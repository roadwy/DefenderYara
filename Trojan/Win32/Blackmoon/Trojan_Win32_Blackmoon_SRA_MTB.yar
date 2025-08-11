
rule Trojan_Win32_Blackmoon_SRA_MTB{
	meta:
		description = "Trojan:Win32/Blackmoon.SRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d8 89 5d e4 8b 5d e4 8a 03 25 ff 00 00 00 89 45 f4 db 45 fc dd 5d e0 dd 45 e0 dc 25 1b 32 49 00 dd 5d d8 dd 45 d8 } //2
	condition:
		((#a_01_0  & 1)*2) >=1
 
}