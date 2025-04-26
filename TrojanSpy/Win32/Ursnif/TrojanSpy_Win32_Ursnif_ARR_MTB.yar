
rule TrojanSpy_Win32_Ursnif_ARR_MTB{
	meta:
		description = "TrojanSpy:Win32/Ursnif.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 30 07 97 01 89 94 30 84 dd ff ff a1 ?? ?? ?? ?? 0f b7 f9 2b c7 83 c6 04 83 e8 17 81 fe 7c 23 00 00 0f 82 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}