
rule Trojan_Win32_Zusy_SXD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.SXD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b fe 8b 36 66 83 7f 2e 00 74 23 8b 4f 30 85 c9 74 1c 51 8d 94 24 14 02 00 00 e8 ?? ?? ?? ?? 8d 94 24 10 02 00 00 51 8b ca e8 ?? ?? ?? ?? 51 8d 54 24 14 8d 8c 24 14 02 00 00 e8 ?? ?? ?? ?? 85 c0 74 08 3b f3 75 b9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}