
rule Trojan_Win32_Pterodo_MKV_MTB{
	meta:
		description = "Trojan:Win32/Pterodo.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {30 0c 06 8d 48 fe 0f b6 54 06 fe 84 d2 74 de 30 54 06 ff eb d8 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}