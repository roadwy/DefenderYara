
rule Ransom_Win32_WastedLocker_SK_MTB{
	meta:
		description = "Ransom:Win32/WastedLocker.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {89 08 5f 5b 5d c3 90 0a f0 00 eb 90 01 01 bb 90 01 04 bb 90 01 04 31 0d 90 01 04 bb 90 01 04 a1 90 01 04 bb 90 01 04 8b ff c7 05 90 01 04 00 00 00 00 01 05 90 01 04 8b ff a1 90 01 04 8b 0d 90 00 } //1
		$a_02_1 = {55 8b ec 53 8b 25 90 01 04 58 8b e8 ff 35 90 01 04 ff 35 90 01 04 8b 1d 90 01 04 8b c0 8b c0 8b c0 8b c0 53 c3 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}