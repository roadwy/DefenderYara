
rule Trojan_Win32_Ursnif_Y_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.Y!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 c0 83 f3 ?? 89 02 83 c2 } //2
		$a_03_1 = {d3 e0 83 c7 ?? 03 d8 4e 85 f6 } //2
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2) >=4
 
}