
rule Trojan_Win32_GhostRat_BAK_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.BAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 99 f7 7d ec 8b 45 10 8a 0c 10 88 4d f3 0f be 55 ff 0f be 45 f3 33 d0 88 55 ff 8b 4d d0 51 6a 01 6a 01 8d 55 ff 52 e8 8f 89 02 00 83 c4 10 8b 45 f8 83 c0 01 89 45 f8 eb } //5
		$a_01_1 = {8b 4d bc 89 4d e4 6a 04 68 00 10 00 00 8b 55 e4 52 6a 00 ff 15 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}