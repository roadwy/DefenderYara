
rule Trojan_Win32_Nymaim_RPY_MTB{
	meta:
		description = "Trojan:Win32/Nymaim.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 45 f8 8b 45 f8 8b 48 1c 89 4d f4 ff 75 14 ff 75 10 ff 75 0c ff 75 08 ff 55 f4 89 45 fc 8b 45 fc 8b e5 5d c2 10 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}