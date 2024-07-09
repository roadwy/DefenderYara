
rule Trojan_Win32_PackZ_AMAB_MTB{
	meta:
		description = "Trojan:Win32/PackZ.AMAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 10 f7 d1 09 c9 81 c7 ?? ?? ?? ?? 81 e2 ff 00 00 00 f7 d7 49 81 e9 ?? 00 00 00 31 16 21 f9 49 46 01 f9 09 fb 81 c3 ?? ?? ?? ?? 40 21 c9 09 db 09 df 81 fe ?? ?? ?? ?? 0f 8c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}