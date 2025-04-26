
rule Trojan_Win32_Pterodo_YAG_MTB{
	meta:
		description = "Trojan:Win32/Pterodo.YAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a 44 11 ff 84 c0 74 03 30 04 11 4a 39 d7 75 f0 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}