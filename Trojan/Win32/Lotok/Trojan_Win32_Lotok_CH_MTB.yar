
rule Trojan_Win32_Lotok_CH_MTB{
	meta:
		description = "Trojan:Win32/Lotok.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 ec 64 56 57 8b f9 50 68 ?? ?? 40 00 8d 4c 24 10 68 ?? ?? 40 00 51 ff 15 ?? ?? 40 00 83 c4 10 8d 54 24 08 52 6a 00 6a 00 ff 15 } //4
		$a_01_1 = {6a 40 68 00 30 00 00 68 5c dc 04 00 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}