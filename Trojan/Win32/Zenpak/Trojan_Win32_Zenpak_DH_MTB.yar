
rule Trojan_Win32_Zenpak_DH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 fe 8b 4d e0 8a 3c 11 8b 75 c8 88 3c 31 88 1c 11 0f b6 0c 31 8b 75 cc 01 f1 81 e1 ff 00 00 00 8b 75 e8 8b 5d d0 8a 1c 1e 8b 75 e0 32 1c 0e 8b 4d e4 8b 75 d0 88 1c 31 8b 4d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}