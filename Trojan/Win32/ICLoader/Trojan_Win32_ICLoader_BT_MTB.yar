
rule Trojan_Win32_ICLoader_BT_MTB{
	meta:
		description = "Trojan:Win32/ICLoader.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 c1 8b 4c 24 0c a2 ?? ?? ?? 00 0c 30 c0 e8 04 25 ff 00 00 00 68 ?? ?? ?? 00 89 44 24 0c 6a 00 db 44 24 10 8d 54 24 1c 6a 01 52 89 4c 24 ?? dc 3d } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}