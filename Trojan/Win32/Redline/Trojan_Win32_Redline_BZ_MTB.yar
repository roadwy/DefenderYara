
rule Trojan_Win32_Redline_BZ_MTB{
	meta:
		description = "Trojan:Win32/Redline.BZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 04 10 69 c0 90 02 04 6b c0 90 01 01 99 bf 90 02 04 f7 ff 99 bf 90 02 04 f7 ff 83 e0 90 01 01 33 f0 03 ce 8b 55 0c 03 55 fc 88 0a 0f be 45 fb 8b 4d 0c 03 4d fc 0f b6 11 2b d0 8b 45 0c 03 45 fc 88 10 eb 90 00 } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}