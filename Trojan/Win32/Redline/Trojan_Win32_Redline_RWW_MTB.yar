
rule Trojan_Win32_Redline_RWW_MTB{
	meta:
		description = "Trojan:Win32/Redline.RWW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 90 01 01 0f be 04 10 69 c0 90 01 04 6b c0 90 01 01 99 bf 90 01 04 f7 ff 25 90 01 04 33 f0 03 ce 8b 55 90 01 01 03 55 90 01 01 88 0a 0f be 45 90 01 01 8b 4d 90 01 01 03 4d 90 01 01 0f b6 11 2b d0 8b 45 90 01 01 03 45 90 01 01 88 10 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}