
rule Trojan_Win32_Tofsee_KAG_MTB{
	meta:
		description = "Trojan:Win32/Tofsee.KAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 db 0b 1f 8d 7f ?? f7 db 83 eb ?? 83 eb ?? 8d 5b ?? 29 d3 53 5a c7 41 ?? ?? ?? ?? ?? 31 19 83 e9 ?? 83 c6 ?? 81 fe ?? ?? ?? ?? 75 d3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}