
rule Trojan_Win32_Tedy_NITA_MTB{
	meta:
		description = "Trojan:Win32/Tedy.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff 36 8d 4c 24 10 e8 24 0c 00 00 83 f8 ff 75 58 83 c6 04 8d 44 24 40 3b f0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}