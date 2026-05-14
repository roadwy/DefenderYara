
rule Trojan_Win32_Zusy_DLH_MTB{
	meta:
		description = "Trojan:Win32/Zusy.DLH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {66 81 ed ed cc 66 81 f5 20 9c 66 c1 fd 07 f9 83 c4 24 54 45 f8 66 89 c5 50 66 31 c5 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}