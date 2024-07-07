
rule Trojan_Win32_Tibs_FF{
	meta:
		description = "Trojan:Win32/Tibs.FF,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 ec e8 69 c0 90 01 04 bf 90 01 04 83 c9 ff 90 03 01 01 41 81 90 02 05 01 c7 90 02 04 96 ad 35 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}