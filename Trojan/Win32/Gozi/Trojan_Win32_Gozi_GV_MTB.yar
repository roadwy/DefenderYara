
rule Trojan_Win32_Gozi_GV_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a d0 2a d6 80 ea 90 01 01 8d 83 90 01 04 81 c1 90 01 04 66 03 f0 89 0d 90 01 04 a1 90 01 04 66 89 35 90 01 04 8a 35 90 01 04 89 8c 38 90 01 04 8a c6 2a 05 90 01 04 83 c7 04 04 90 01 01 02 d0 a0 90 01 04 81 ff 90 01 04 0f 82 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}