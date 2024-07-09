
rule Trojan_Win32_Bublik_GZX_MTB{
	meta:
		description = "Trojan:Win32/Bublik.GZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {54 44 2b e3 41 81 f4 ?? ?? ?? ?? 66 45 0f ab fc 31 1c 24 41 5c 40 f6 c6 b1 3c 88 48 63 db 48 03 eb ff e5 } //5
		$a_01_1 = {66 d3 d1 80 ea 8d 32 da f6 dd 66 ff c9 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}