
rule Trojan_Win32_Bunitucryt_RM_MTB{
	meta:
		description = "Trojan:Win32/Bunitucryt.RM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2d 00 10 00 00 83 c0 04 90 09 3c 00 [0-20] 31 [0-12] 04 [0-12] 04 01 45 ?? 8b [0-05] 3b [0-05] 72 [0-05] 8b } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}