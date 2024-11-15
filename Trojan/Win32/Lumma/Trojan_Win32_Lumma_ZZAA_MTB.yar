
rule Trojan_Win32_Lumma_ZZAA_MTB{
	meta:
		description = "Trojan:Win32/Lumma.ZZAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {57 89 5c 24 ?? 33 c9 33 d2 88 4c 0c ?? 6a 27 8b c1 5f f7 f7 8a 04 32 88 84 0c ?? ?? 00 00 41 3b cd 7c e4 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}