
rule Trojan_Win32_Redline_CAD_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 08 0f be 04 10 69 c0 [0-04] 99 bf [0-04] f7 ff 6b c0 ?? 6b c0 ?? 83 e0 13 ?? f0 03 ce 8b 55 0c 03 55 dc 88 0a 0f be 45 db 8b 4d 0c 03 4d dc 0f b6 11 2b d0 8b 45 0c 03 45 dc 88 10 eb } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}