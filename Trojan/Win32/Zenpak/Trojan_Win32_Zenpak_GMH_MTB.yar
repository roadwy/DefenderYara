
rule Trojan_Win32_Zenpak_GMH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 c6 85 91 90 01 03 6e c6 85 92 90 01 03 74 c6 85 93 90 01 03 65 c6 85 94 90 01 03 72 c6 85 95 90 01 03 6e c6 85 96 90 01 03 65 c6 85 97 90 01 03 74 c6 85 98 90 01 03 52 c6 85 99 90 01 03 65 c6 85 9a 90 01 03 61 c6 85 9b 90 01 03 64 c6 85 9c 90 01 03 46 c6 85 9d 90 01 03 69 c6 85 9e 90 01 03 6c c6 85 9f 90 01 03 65 c6 85 a0 90 01 03 00 6a 00 6a 00 6a 00 6a 00 8d 8d 90 01 04 51 ff 15 90 00 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}