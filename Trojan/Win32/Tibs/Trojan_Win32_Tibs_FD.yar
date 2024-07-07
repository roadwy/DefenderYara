
rule Trojan_Win32_Tibs_FD{
	meta:
		description = "Trojan:Win32/Tibs.FD,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c5 83 ed 90 01 01 83 ed 90 01 01 66 09 ed 90 02 01 74 05 05 00 02 00 00 89 ea 09 ea 90 02 01 75 90 01 01 bf 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}