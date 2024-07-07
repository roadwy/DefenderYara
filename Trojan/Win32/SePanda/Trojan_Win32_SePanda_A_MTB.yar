
rule Trojan_Win32_SePanda_A_MTB{
	meta:
		description = "Trojan:Win32/SePanda.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 8d 44 24 20 68 90 01 02 40 00 50 ff 90 01 01 8a 44 24 5c 83 c4 0c 84 c0 8d 74 24 50 90 01 02 8d 4c 24 1c 51 56 ff 90 01 01 85 c0 90 01 02 6a 00 56 e8 90 01 02 00 00 83 c4 08 40 8b f0 80 3e 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}