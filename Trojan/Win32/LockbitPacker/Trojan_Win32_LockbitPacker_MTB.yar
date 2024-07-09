
rule Trojan_Win32_LockbitPacker_MTB{
	meta:
		description = "Trojan:Win32/LockbitPacker!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 4d fc 83 c1 01 89 4d fc 8b 55 fc 3b 55 0c 73 1c 0f b6 05 ?? ?? ?? ?? 8b 4d 08 03 4d fc 0f b6 11 2b d0 8b 45 08 03 45 fc 88 10 eb d3 b8 ?? ?? ?? ?? 8b e5 5d } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}