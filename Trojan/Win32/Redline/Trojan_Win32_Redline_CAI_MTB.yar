
rule Trojan_Win32_Redline_CAI_MTB{
	meta:
		description = "Trojan:Win32/Redline.CAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b 45 08 0f be 0c 10 6b c9 4c 83 f1 03 8b 55 0c 03 55 dc 0f b6 02 33 c1 8b 4d 0c 03 4d dc 88 01 eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}