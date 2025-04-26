
rule Trojan_Win32_Redline_CAG_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 ff 8b 45 08 0f be 14 10 69 d2 [0-04] 83 e2 0e 33 f2 83 f6 06 03 ce 8b 45 0c 03 45 dc 88 08 0f be 4d db 8b 55 0c 03 55 dc 0f b6 02 2b c1 8b 4d 0c 03 4d dc 88 01 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}