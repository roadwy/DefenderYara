
rule Trojan_Win32_Tibs_FF{
	meta:
		description = "Trojan:Win32/Tibs.FF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 ec e8 69 c0 ?? ?? ?? ?? bf ?? ?? ?? ?? 83 c9 ff (41|81) [0-05] 01 c7 [0-04] 96 ad 35 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}