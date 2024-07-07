
rule Trojan_Win64_Redline_MB_MTB{
	meta:
		description = "Trojan:Win64/Redline.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {f7 f9 8b c2 48 63 8d 80 02 00 00 48 8b 95 78 02 00 00 89 04 8a eb } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}