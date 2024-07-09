
rule Trojan_Win32_Tibs_IK{
	meta:
		description = "Trojan:Win32/Tibs.IK,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 19 0f c1 5d fc bb ?? ?? ?? ?? 81 f3 ?? ?? ?? ?? 8d 55 f4 52 53 50 56 ff 55 fc } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}