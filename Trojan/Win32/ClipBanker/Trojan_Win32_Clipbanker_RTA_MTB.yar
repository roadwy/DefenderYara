
rule Trojan_Win32_Clipbanker_RTA_MTB{
	meta:
		description = "Trojan:Win32/Clipbanker.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6b c0 28 8b 80 90 01 04 33 d2 f7 35 90 01 04 a3 90 01 04 a1 90 01 04 83 c0 01 a3 90 01 04 a1 90 01 04 0f af 05 90 01 04 a3 90 01 04 a1 90 01 04 03 05 90 01 04 a3 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}