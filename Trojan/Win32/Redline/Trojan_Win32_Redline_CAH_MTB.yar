
rule Trojan_Win32_Redline_CAH_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 08 0f be 14 10 69 d2 90 02 04 81 e2 6b 01 00 00 33 f2 03 ce 8b 45 0c 03 45 80 88 08 0f be 8d 7f ff ff ff 8b 55 0c 03 55 80 0f b6 02 2b c1 8b 4d 0c 03 4d 80 88 01 eb 90 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}