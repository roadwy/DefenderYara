
rule Trojan_Win32_Ursnif_GF_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 f3 33 b5 [0-20] 2b fe 25 [0-20] 81 6d [0-20] bb [0-20] 81 45 [0-20] 8b 4d ?? 83 25 [0-20] 8b c7 d3 e0 8b cf c1 e9 ?? 03 8d [0-40] 33 c1 8b 8d } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}