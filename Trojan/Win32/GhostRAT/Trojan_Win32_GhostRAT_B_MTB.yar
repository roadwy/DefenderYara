
rule Trojan_Win32_GhostRAT_B_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 4d 88 ff d6 80 65 0b 00 ff 15 ?? 21 40 00 99 b9 00 01 00 00 68 00 28 00 00 f7 f9 8d 45 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}