
rule Trojan_Win32_TimbreStealer_BAB_MTB{
	meta:
		description = "Trojan:Win32/TimbreStealer.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c0 0f b6 44 04 ?? 32 44 2b ff 88 43 ff 83 ee 01 75 30 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}