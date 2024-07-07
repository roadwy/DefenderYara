
rule Trojan_Win32_Fauppod_MJ_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 f2 68 88 54 24 68 8a 44 24 68 8a d0 02 c0 c0 ea 07 0a d0 8b 74 24 64 8a c2 04 f3 8a 9e 90 01 04 02 d8 88 5c 34 10 46 81 e6 ff 00 00 00 89 74 24 64 83 fe 4c 7c 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}