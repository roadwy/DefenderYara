
rule Ransom_Win32_WastedLocker_WT_MTB{
	meta:
		description = "Ransom:Win32/WastedLocker.WT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 16 8b c2 23 c1 8b fa 0b f9 f7 d0 23 c7 8b c8 23 90 02 04 0b 90 02 04 f7 d1 23 c8 8b 90 02 04 83 90 02 04 04 89 08 8a cb d3 ca 83 c6 04 4b 8b ca 75 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}