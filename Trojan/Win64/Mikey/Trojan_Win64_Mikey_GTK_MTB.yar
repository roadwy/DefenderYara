
rule Trojan_Win64_Mikey_GTK_MTB{
	meta:
		description = "Trojan:Win64/Mikey.GTK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {d3 e2 30 9e ?? ?? ?? ?? a3 ?? ?? ?? ?? ?? ?? ?? ?? d2 d0 54 a3 ?? ?? ?? ?? ?? ?? ?? ?? 6a d0 54 a3 } //5
		$a_03_1 = {f7 d1 c1 c9 ?? 44 31 4c 54 ?? 41 ff c9 ff c9 f7 d9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}