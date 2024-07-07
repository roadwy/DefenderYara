
rule Trojan_Win32_Glupteba_DHD_MTB{
	meta:
		description = "Trojan:Win32/Glupteba.DHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b f8 8b 45 90 01 01 d1 6d 90 01 01 29 45 90 01 01 ff 4d 90 01 01 0f 85 90 01 04 81 3d 90 01 04 61 01 00 00 5b 90 13 8b 45 90 01 01 8b 4d 90 01 01 89 48 90 01 01 8b 4d 90 01 01 89 38 5f 33 cd 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}