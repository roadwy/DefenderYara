
rule Trojan_Win32_Zenpak_CCIM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.CCIM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d0 31 25 ?? ?? ?? 00 89 d0 e8 15 00 00 00 b8 06 00 00 00 8d 05 10 10 ?? 00 01 30 8d 05 f5 11 ?? 00 50 c3 8d 05 1c ?? ?? 00 89 28 83 c0 09 83 f0 05 89 1d 18 10 ?? 00 89 c2 31 3d 14 10 ?? 00 eb cd } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}